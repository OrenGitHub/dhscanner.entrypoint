import os
import re
import sys
import glob
import json
import enum
import magic
import typing
import shutil
import tarfile
import logging
import fastapi
import slowapi
import tempfile
import requests
import dataclasses
import collections
import generate_sarif


app = fastapi.FastAPI()

# every client must have an approved bearer token to access
# locally deployed webservers are supported - no need for bearer tokens
EXPECTED_TOKEN = os.getenv('APPROVED_BEARER_TOKEN_0', '')

# every client must have an approved url to access
# (one url per client, which is also rate limited)
# locally deployed webservers are supported - no need for approved urls
NUM_APPROVED_URLS = os.getenv('NUM_APPROVED_URLS', '1')
APPROVED_URLS = [os.getenv(f'APPROVED_URL_{i}', 'scan') for i in range(int(NUM_APPROVED_URLS))]

limiter = slowapi.Limiter(key_func=lambda request: request.client.host)

# generate as many request handlers as needed
# each request handler listens to one approved url
# pylint: disable=cell-var-from-loop,redefined-outer-name
def create_handlers(approved_url: str):

    @app.post(f'/{approved_url}')
    @limiter.limit('60/minute')
    async def entrypoint(request: fastapi.Request, authorization: typing.Optional[str] = fastapi.Header(None)):
        return await scan(request, authorization)

    @app.get(f'/{approved_url}/healthcheck')
    @limiter.limit('60/minute')
    def healthcheck(request: fastapi.Request, authorization: typing.Optional[str] = fastapi.Header(None)):

        if authorization is None:
            raise fastapi.HTTPException(
                status_code=401,
                detail='Missing authorization header'
            )

        accept = request.headers.get('accept', '').casefold()
        if accept != "application/json":
            raise fastapi.HTTPException(
                status_code=406,
                detail="Invalid content type"
            )

        return { 'healthy': True, 'Accept': accept }

for approved_url in APPROVED_URLS:
    create_handlers(approved_url)

class Language(str, enum.Enum):
    JS = 'js'
    TS = 'ts'
    PHP = 'php'
    PY = 'py'
    RB = 'rb'
    BLADE_PHP = 'blade.php'

AST_BUILDER_URL = {
    Language.JS: 'http://frontjs:3000/to/esprima/js/ast',
    Language.TS: 'http://frontts:8008/to/native/ts/ast',
    Language.PHP: 'http://frontphp:5000/to/php/ast',
    Language.PY: 'http://frontpy:5000/to/native/py/ast',
    Language.RB: 'http://frontrb:8007/to/native/cruby/ast',
    Language.BLADE_PHP: 'http://frontphp:5000/to/php/code'
}

DHSCANNER_AST_BUILDER_URL = {
    Language.JS: 'http://parsers:3000/from/js/to/dhscanner/ast',
    Language.TS: 'http://parsers:3000/from/ts/to/dhscanner/ast',
    Language.PHP: 'http://parsers:3000/from/php/to/dhscanner/ast',
    Language.PY: 'http://parsers:3000/from/py/to/dhscanner/ast',
    Language.RB: 'http://parsers:3000/from/rb/to/dhscanner/ast',
}

CSRF_TOKEN = 'http://frontphp:5000/csrf_token'

TO_CODEGEN_URL = 'http://codegen:3000/codegen'
TO_KBGEN_URL = 'http://kbgen:3000/kbgen'
TO_QUERY_ENGINE_URL = 'http://queryengine:5000/check'

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s]: %(message)s",
    datefmt="%d/%m/%Y ( %H:%M:%S )",
    stream=sys.stdout
)

# TODO: adjust other reasons for exclusion
# the reasons might depend on the language
# (like the third party directory name: node_module for javascript,
# site-packages for python or vendor/bundle for ruby etc.)
# pylint: disable=unused-argument
def scan_this_file(filename: str, language: Language, ignore_testing_code: bool = False) -> bool:
    if ignore_testing_code and 'test' in filename:
        return False

    return True

def collect_sources(workdir: str, language: Language, files: dict[Language,list[str]], ignore_testing_code: bool) -> None:

    filenames = glob.glob(f'{workdir}/**/*.{language.value}', recursive=True)
    for filename in filenames:
        if os.path.isfile(filename):
            if scan_this_file(filename, language, ignore_testing_code):
                files[language].append(filename)

def collect_all_sources(workdir: str, ignore_testing_code: bool):

    files = collections.defaultdict(list) # type: ignore[var-annotated]
    for language in Language:
        collect_sources(workdir, language, files, ignore_testing_code)

    return files

def read_single_file(filename: str):

    with open(filename, 'r', encoding='utf-8') as fl:
        code = fl.read()

    return { 'source': (filename, code) }

# Laravel has a built-in csrf token demand
# There are other options too, but currently
# I'm sticking to Laravel ... this means that all
# the php files should be added using the same session
def add_php_asts(files: dict[Language, list[str]], asts: dict) -> None:

    session = requests.Session()
    response = session.get(CSRF_TOKEN)
    token = response.text
    cookies = session.cookies
    headers = { 'X-CSRF-TOKEN': token }

    filenames = files[Language.PHP]
    for filename in filenames:
        if filename in files[Language.BLADE_PHP]:
            just_one_blade_php_file = read_single_file(filename)
            response = session.post(
                AST_BUILDER_URL[Language.BLADE_PHP],
                files=just_one_blade_php_file,
                headers=headers,
                cookies=cookies
            )
            php_source_code = { 'source': (filename, response.text) }
        else:
            php_source_code = read_single_file(filename)

        # from here on, plain php code
        response = session.post(
            AST_BUILDER_URL[Language.PHP],
            files=php_source_code,
            headers=headers,
            cookies=cookies
        )
        asts[Language.PHP].append({
            'filename': filename,
            'actual_ast': response.text
        })

        if filename.endswith('handesk/app/Ticket.php'):
            logging.info(response.text)

def add_ast(filename: str, language: Language, asts: dict) -> None:

    one_file_at_a_time = read_single_file(filename)
    response = requests.post(AST_BUILDER_URL[language], files=one_file_at_a_time)
    asts[language].append({ 'filename': filename, 'actual_ast': response.text })

    #if filename.endswith('sickchill/sickchill/views/authentication.py'):
    #    logging.info(response.text)

def parse_code(files: dict[Language, list[str]]) -> dict[Language, list[dict[str, str]]]:

    asts = collections.defaultdict(list) # type: ignore[var-annotated]

    for language, filenames in files.items():
        if language not in [Language.PHP, Language.BLADE_PHP]:
            for filename in filenames:
                add_ast(filename, language, asts)

    # separately because php chosen webserver
    # has a more complex sessio mechanism
    # see more details inside the function
    # it handles both plain php files and blade.php files
    add_php_asts(files, asts)

    return asts

def add_dhscanner_ast(filename: str, language: Language, code, asts) -> None:

    content = { 'filename': filename, 'content': code}
    url = DHSCANNER_AST_BUILDER_URL[language]
    response = requests.post(f'{url}?filename={filename}', json=content)
    asts[language].append({ 'filename': filename, 'dhscanner_ast': response.text })

    #if filename.endswith('sickchill/sickchill/views/authentication.py'):
    #    logging.info(response.text)

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
    return response.text

# pylint: disable=consider-using-with,logging-fstring-interpolation
def query_engine(kb_filename: str, queries_filename: str, debug: bool) -> str:

    kb_and_queries = {
        'kb': ('kb', open(kb_filename, encoding='utf-8')),
        'queries': ('queries', open(queries_filename, encoding='utf-8')),
    }

    url = f'{TO_QUERY_ENGINE_URL}'
    response = requests.post(url, files=kb_and_queries, data={'debug': json.dumps(debug)})
    return response.text

def patternify() -> str:
    start = r'startloc_(\d+)_(\d+)'
    end = r'endloc_(\d+)_(\d+)'
    fname = r'([a-z0-9]*[_slash_[a-z0-9]*]*)_dot_py'
    loc = fr'{start}_{end}_{fname}'
    edge = fr'\({loc},{loc}\)'
    path = fr'{edge}(,{edge})*'
    query = r'q(\d+)'
    return fr'{query}\(\[{path}\]\): yes'

# pylint: disable=too-many-locals,too-many-branches,too-many-statements,logging-fstring-interpolation
async def scan(request: fastapi.Request, authorization: typing.Optional[str] = fastapi.Header(None)) -> dict:

    if authorization is None:
        raise fastapi.HTTPException(
            status_code=401,
            detail='Missing authorization header'
        )

    logging.info('[ step 1 ] relevant headers ....  : yes 😃 ')

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
        raise fastapi.HTTPException(
            status_code=400,
            detail="Invalid content type"
        )

    logging.info('[ step 1 ] streamed tar file .... : yes 😃 ')

    repo_name = request.headers.get('X-Directory-Name')
    if repo_name is None:
        raise fastapi.HTTPException(
            status_code=400,
            detail='repo name (via X-Directory-Name header) is missing'
        )

    logging.info('[ step 1 ] repo name received ... : yes 😃 ')

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        tar_filename = f.name
        async for chunk in request.stream():
            f.write(chunk)

    logging.info('[ step 1 ] completed tar file ... : yes 😃 ')

    workdir = tempfile.mkdtemp()
    with tarfile.open(name=tar_filename) as tar:
        tar.extractall(path=workdir, filter='tar')

    logging.info('[ step 1 ] extracted tar file ... : yes 😃 ')

    os.remove(tar_filename)

    logging.info('[ step 1 ] deleted tar file ..... : yes 😃 ')

    # the following code block handles docker images
    # for simple file systems like a tar-ed repo sent from CI/CD
    # this entire block does nothing ...
    layers = glob.glob(f'{workdir}/**/*', recursive=True)
    for layer in layers:
        if os.path.isfile(layer) and 'POSIX tar archive' in magic.from_file(layer):
            layertar = tarfile.open(name=layer)
            dirname = os.path.dirname(layer)
            layertar.extractall(path=dirname, filter='tar')
            layertar.close()

    ignore_testing_code_str = request.headers.get('Ignore-Testing-Code', 'false').lower()
    ignore_testing_code = (ignore_testing_code_str in ['yes', 'true'])

    files = collect_all_sources(workdir, ignore_testing_code)

    logging.info('[ step 2 ] native asts .......... : started  😃 ')

    language_asts = parse_code(files)

    logging.info('[ step 2 ] native asts .......... : finished 😃 ')

    # before the entire working directory is deleted,
    # make sure to copy the queries file
    with tempfile.NamedTemporaryFile(delete=False) as queries_file:
        queries_filename = queries_file.name
        dhscanner_queries = os.path.join(workdir, '.dhscanner.queries')
        try:
            shutil.copy(dhscanner_queries, queries_filename)
        except FileNotFoundError as e:
            raise fastapi.HTTPException(
                status_code=400,
                detail='file .dhscanner.queries missing from repo'
            ) from e

    # actual source files are no longer needed
    # everything is inside the language asts
    # .dhscanner.queries was copied to another location
    shutil.rmtree(workdir)

    logging.info('[ step 2 ] deleting all src files : finished 😃 ')

    dhscanner_asts = parse_language_asts(language_asts)

    valid_dhscanner_asts = []
    total_num_files: dict[Language, int] = collections.defaultdict(int)
    num_parse_errors: dict[Language, int] = collections.defaultdict(int)

    for language, asts in dhscanner_asts.items():
        for ast in asts:
            try:
                actual_ast = json.loads(ast['dhscanner_ast'])
                if 'status' in actual_ast and 'filename' in actual_ast and actual_ast['status'] == 'FAILED':
                    num_parse_errors[language] += 1
                    total_num_files[language] += 1
                    #filename = actual_ast['filename']
                    #message = actual_ast['message']
                    #if language == Language.PY:
                    #    if filename.endswith('sickchill/sickchill/views/authentication.py'):
                    #        logging.info(f'FAILED({message}): {filename}')
                    continue

            except ValueError:
                continue

            valid_dhscanner_asts.append(actual_ast)
            total_num_files[language] += 1

    for language in dhscanner_asts.keys():
        n = total_num_files[language]
        errors = num_parse_errors[language]
        logging.info(f'[ step 2 ] dhscanner ast ( {language.value} )   : {n - errors}/{n}')

    bitcodes = codegen(valid_dhscanner_asts)

    logging.info('[ step 2 ] dhscanner asts ....... : finished 😃 ')

    content = bitcodes['content']

    try:
        bitcode_as_json = json.loads(content)
        logging.info('[ step 3 ] code gen ............. : finished 😃 ')
    except ValueError as e:
        logging.info('[ step 3 ] code gen ............. : failed 😬 ')
        logging.info(content)
        raise fastapi.HTTPException(
            status_code=400,
            detail='code generation failed'
        ) from e

    logging.info('[ step 4 ] knowledge base gen ... : started  😃 ')

    kb = kbgen(bitcode_as_json)

    try:
        content = json.loads(kb)['content']
        logging.info('[ step 4 ] knowledge base gen ... : finished 😃 ')
    except json.JSONDecodeError as e:
        logging.warning('[ step 4 ] knowledge base gen ... : failed 😬 ')
        logging.warning(kb['content'])
        raise fastapi.HTTPException(
            status_code=400,
            detail='knowledge base generation failed'
        ) from e

    with tempfile.NamedTemporaryFile(suffix=".pl", mode='w', delete=False) as f:
        kb_filename = f.name
        dummy_classloc = 'not_a_real_loc'
        dummy_classname = "'not_a_real_classnem'"
        f.write(f'kb_class_name( {dummy_classloc}, {dummy_classname}).\n')
        f.write('\n'.join(sorted(set(content))))
        f.write('\n')

    logging.info('[ step 5 ] prolog file gen ...... : finished 😃 ')
    logging.info('[ step 6 ] query engine ......... : starting 🙏 ')

    debug_queryengine = json.loads(request.headers.get('X-Debug-Queryengine', 'false'))
    result = query_engine(kb_filename, queries_filename, debug_queryengine)
    os.remove(queries_filename)

    messages = []
    for language in Language:
        total = total_num_files[language]
        errors = num_parse_errors[language]
        message = f'{language.value}={total-errors}/{total}'
        if total - errors > 0:
            messages.append(message)

    # this is an efficient debug tool
    # pylint: disable=unused-variable
    repo_info = ','.join(messages)
    all_kb_facts = sorted(set(content))
    facts = []
    for fact in all_kb_facts:
        fact_part = request.headers.get('X-Relevant-Facts')
        if fact_part is not None:
            if fact_part in fact:
                facts.append(fact)

    logging.info('[ step 7 ] deleted query file ... : finished 😃 ')

    pattern = patternify()
    filename = repo_name
    region = generate_sarif.Region.make_default()
    if match := re.search(pattern, result):
        # TODO: propagate the query number inside the Sarif output
        query_number = int(match.group(1)) # pylint: disable=unused-variable
        lineStart = int(match.group(2))
        colStart = int(match.group(3))
        lineEnd = int(match.group(4))
        colEnd = int(match.group(5))
        filename = match.groups()[-1]
        region = generate_sarif.Region(
            startLine=lineStart,
            endLine=lineEnd,
            startColumn=colStart,
            endColumn=colEnd
        )

    sarif = generate_sarif.run(
        filename.replace('_slash_', '/') + '.py',
        'open redirect',
        region
    )

    logging.info('[ step 8 ] sarif response ....... : finished 😃 ')
    logging.info('[ step 9 ] sending response now   :  🚀 ')

    return dataclasses.asdict(sarif)
