import os
import glob
import json
import enum
import magic
import typing
import asyncio
import logging
import fastapi
import collections


from fastapi.responses import JSONResponse

# the entire repo is tar-ed and streamed to the endpoint
# the queries are tar-ed as well as a .dhscanner file
import tempfile

app = fastapi.FastAPI()

# Expected Bearer token (stored securely in an environment variable)
EXPECTED_TOKEN = os.getenv("BEARER_TOKEN", "my-secure-token")

class Language(str, enum.Enum):
    JS = 'js'
    TS = 'ts'
    PHP = 'php'
    PY = 'py'
    RB = 'rb'

def collect_sources(workdir: str, language: Language, files: dict[Language,list[str]]) -> None:

    filenames = glob.glob(f'{workdir}/**/*.{language.value}', recursive=True)
    for filename in filenames:
        if os.path.isfile(filename):
            if scan_this_file(filename, language):
                files[language].append(filename)

def collect_all_sources(workdir: str):

    files = collections.defaultdict(list)
    for language in Language:
        collect_sources(workdir, language, files)

    return files

@app.post('/scan')
async def scan(request: fastapi.Request, authorization: typing.Optional[str] = fastapi.Header(None)):

    if authorization is None:
        raise fastapi.HTTPException(
            status_code=401,
            detail='Missing authorization header'
        )

    if not authorization.startswith('Bearer '):
        raise fastapi.HTTPException(
            status_code=401,
            detail='Invalid authorization header'
        )

    token = authorization[len('Bearer '):]
    if token != EXPECTED_TOKEN:
        raise fastapi.HTTPException(
            status_code=403,
            detail="Invalid Bearer token"
        )

    content_type = request.headers.get("content-type")
    if content_type != "application/octet-stream":
        raise HTTPException(
            status_code=400,
            detail="Invalid content type"
        )

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        filename = f.name
        async for chunk in request.stream():
            f.write(chunk)

    workdir = tempfile.mkdtemp()
    tarfile.open(name=filename).extractall(path=workdir, filter='tar').close()

    layers = glob.glob(f'{workdir}/**/*', recursive=True)
    for layer in layers:
        if os.path.isfile(layer) and 'POSIX tar archive' in magic.from_file(layer):
            layertar = tarfile.open(name=layer)
            dirname = os.path.dirname(layer)
            layertar.extractall(path=dirname, filter='tar')
            layertar.close()

    files = collect_all_sources(args)
    language_asts = parse_code(files)
    dhscanner_asts = asyncio.run(parse_language_asts(language_asts))

    total_num_files: dict[str,int] = collections.defaultdict(int)
    num_parse_errors: dict[str,int] = collections.defaultdict(int)
    for language, asts in dhscanner_asts.items():
        for ast in asts:
            try:
                actual_ast = json.loads(ast['dhscanner_ast'])
                if 'status' in actual_ast and 'filename' in actual_ast and actual_ast['status'] == 'FAILED':
                    num_parse_errors[language] += 1
                    total_num_files[language] += 1
                    filename = actual_ast['filename']
                    message = actual_ast['message']
                    if language == 'py':
                        if filename.endswith('workdir/pghoard/pghoard/transfer.py'):
                            logging.info(f'FAILED({message}): {filename}')
                    continue

            except ValueError:
                continue

            # file succeeded
            #if actual_ast['filename'].endswith('version_helper.rb'):
            #    logging.info(json.dumps(actual_ast, indent=4))
            valid_dhscanner_asts[language].append(actual_ast)
            total_num_files[language] += 1

    for language in dhscanner_asts.keys():
        n = total_num_files[language]
        errors = num_parse_errors[language]
        logging.info(f'[ step 2 ] dhscanner ast ( {language} )   : {n - errors}/{n}')

    bitcodes = codegen(
        valid_dhscanner_asts['js'] +
        valid_dhscanner_asts['py'] +
        valid_dhscanner_asts['rb'] +
        valid_dhscanner_asts['php']
    )

    logging.info('[ step 2 ] dhscanner asts ....... : finished 😃 ')

    content = bitcodes['content']

    try:
        bitcode_as_json = json.loads(content)
        logging.info('[ step 3 ] code gen ............. : finished 😃 ')
    except ValueError:
        logging.info('[ step 3 ] code gen ............. : failed 😬 ')
        logging.info(content)
        return

    kb = kbgen(bitcode_as_json)

    try:
        content = json.loads(kb['content'])['content']
        logging.info('[ step 4 ] knowledge base gen ... : finished 😃 ')
    except json.JSONDecodeError:
        logging.warning('[ step 4 ] knowledge base gen ... : failed 😬 ')
        logging.warning(kb['content'])
        return

    with open('kb.pl', 'w') as fl:
        dummy_classloc = 'not_a_real_loc'
        dummy_classname = "'not_a_real_classnem'"
        fl.write(f'kb_class_name( {dummy_classloc}, {dummy_classname}).\n')
        fl.write('\n'.join(sorted(set(content))))
        fl.write('\n')

    logging.info('[ step 5 ] prolog file gen ...... : finished 😃 ')
    logging.info('[  cves  ] ...................... : starting 🙏 ')

    query_engine('kb.pl', 'queries.pl')