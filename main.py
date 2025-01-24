import os
import sys
import glob
import json
import enum
import magic
import typing
import tarfile
import asyncio
import logging
import fastapi
import requests
import collections


from fastapi.responses import JSONResponse

# the entire repo is tar-ed and streamed to the endpoint
# the queries are tar-ed as well as a .dhscanner file
import tempfile

app = fastapi.FastAPI()

# Expected Bearer token (stored securely in an environment variable)
EXPECTED_TOKEN = os.getenv("APPROVED_BEARER_TOKEN_1", "my-secure-token")

class Language(str, enum.Enum):
    JS = 'js'
    TS = 'ts'
    PHP = 'php'
    PY = 'py'
    RB = 'rb'

AST_BUILDER_URL = {
    Language.JS: 'http://frontjs:3000/to/esprima/js/ast',
    Language.TS: 'http://127.0.0.1:8008/to/native/ts/ast',
    Language.PHP: 'http://127.0.0.1:5000/to/php/ast',
    Language.PY: 'http://frontpy:5000/to/native/py/ast',
    Language.RB: 'http://127.0.0.1:8007/to/native/cruby/ast'
}

DHSCANNER_AST_BUILDER_URL = {
    Language.JS: 'http://parsers:3000/from/js/to/dhscanner/ast',
    Language.TS: 'http://parsers:3000/from/ts/to/dhscanner/ast',
    Language.PHP: 'http://parsers:3000/from/php/to/dhscanner/ast',
    Language.PY: 'http://parsers:3000/from/py/to/dhscanner/ast',
    Language.RB: 'http://parsers:3000/from/rb/to/dhscanner/ast',
}

TO_CODEGEN_URL = 'http://codegen:3000/codegen'
TO_KBGEN_URL = 'http://kbgen:3000/kbgen'
TO_QUERY_ENGINE_URL = 'http://queryengine:5000/check'

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s]: %(message)s",
    datefmt="%d/%m/%Y ( %H:%M:%S )",
    stream=sys.stdout
)

def scan_this_file(filename: str, language: Language) -> bool:
    return True

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

def read_single_file(filename: str):

    with open(filename) as fl:
        code = fl.read()

    return { 'source': ('source', code) }

def add_ast(filename: str, language: Language, asts: dict) -> None:

    one_file_at_a_time = read_single_file(filename)
    response = requests.post(AST_BUILDER_URL[language], files=one_file_at_a_time)
    asts[language].append({ 'filename': filename, 'actual_ast': response.text })

def parse_code(files: dict[Language, list[str]]):

    asts = collections.defaultdict(list)

    for language, filenames in files.items():
        for filename in filenames:
            add_ast(filename, language, asts)

    return asts

def add_dhscanner_ast(filename: str, language: Language, code, asts) -> None:

    content = { 'filename': filename, 'content': code}
    response = requests.post(DHSCANNER_AST_BUILDER_URL[language], json=content)
    asts[language].append({ 'filename': filename, 'dhscanner_ast': response.text })


def parse_language_asts(language_asts):

    dhscanner_asts = collections.defaultdict(list)

    for language, asts in language_asts.items():
        for ast in asts:
            add_dhscanner_ast(ast['filename'], language, ast['actual_ast'], dhscanner_asts)

    return dhscanner_asts

def codegen(dhscanner_asts):

    content = { 'asts': dhscanner_asts }
    response = requests.post(TO_CODEGEN_URL, json=content)
    return { 'content': response.text }


def kbgen(callables):

    response = requests.post(TO_KBGEN_URL, json=callables)
    return { 'content': response.text }

def query_engine(kb_filename: str, queries_filename: str):

    kb_and_queries = {
        'kb': ('kb', open(kb_filename)),
        'queries': ('queries', open(queries_filename)),
    }

    url = f'{TO_QUERY_ENGINE_URL}'
    response = requests.post(url, files=kb_and_queries)
    logging.info(f'[  scan  ] .............. : {response.text}')

@app.post('/scan')
async def scan(request: fastapi.Request, authorization: typing.Optional[str] = fastapi.Header(None)):

    if authorization is None:
        raise fastapi.HTTPException(
            status_code=401,
            detail='Missing authorization header'
        )

    logging.info('[ step 0 ] authorization present  : yes 😃 ')

    if not authorization.startswith('Bearer '):
        raise fastapi.HTTPException(
            status_code=401,
            detail='Invalid authorization header'
        )

    logging.info('[ step 1 ] bearer token exists .. : yes 😃 ')

    token = authorization[len('Bearer '):]
    if token != EXPECTED_TOKEN:
        raise fastapi.HTTPException(
            status_code=403,
            detail="Invalid Bearer token"
        )

    logging.info('[ step 1 ] bearer token is valid  : yes 😃 ')

    content_type = request.headers.get("content-type")
    if content_type != "application/octet-stream":
        raise HTTPException(
            status_code=400,
            detail="Invalid content type"
        )

    logging.info('[ step 1 ] streamed tar file .... : yes 😃 ')

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        filename = f.name
        async for chunk in request.stream():
            f.write(chunk)

    logging.info('[ step 1 ] completed tar file ... : yes 😃 ')

    repo_name = request.headers.get('X-Directory-Name')
    if repo_name is None:
        raise HTTPException(
            status_code=400,
            detail='repo name (via X-Directory-Name header) is missing'
        )

    logging.info('[ step 1 ] repo name received ... : yes 😃 ')

    workdir = tempfile.mkdtemp()
    t = tarfile.open(name=filename)
    t.extractall(path=workdir, filter='tar')
    t.close()

    layers = glob.glob(f'{workdir}/**/*', recursive=True)
    for layer in layers:
        if os.path.isfile(layer) and 'POSIX tar archive' in magic.from_file(layer):
            layertar = tarfile.open(name=layer)
            dirname = os.path.dirname(layer)
            layertar.extractall(path=dirname, filter='tar')
            layertar.close()

    files = collect_all_sources(workdir)
    language_asts = parse_code(files)
    dhscanner_asts = parse_language_asts(language_asts)

    valid_dhscanner_asts: dict = collections.defaultdict(list)
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

            valid_dhscanner_asts[language].append(actual_ast)
            total_num_files[language] += 1

    for language in dhscanner_asts.keys():
        n = total_num_files[language]
        errors = num_parse_errors[language]
        logging.info(f'[ step 2 ] dhscanner ast ( {language.value} )   : {n - errors}/{n}')

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

    with tempfile.NamedTemporaryFile(suffix=".pl", mode='w', delete=False) as f:
        kb_filename = f.name
        dummy_classloc = 'not_a_real_loc'
        dummy_classname = "'not_a_real_classnem'"
        f.write(f'kb_class_name( {dummy_classloc}, {dummy_classname}).\n')
        f.write('\n'.join(sorted(set(content))))
        f.write('\n')

    logging.info('[ step 5 ] prolog file gen ...... : finished 😃 ')
    logging.info('[  scan  ] ...................... : starting 🙏 ')

    queries_filename = os.path.join(workdir, repo_name, '.dhscanner.queries')
    query_engine(kb_filename, queries_filename)

