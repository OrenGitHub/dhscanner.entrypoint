import os
import re
import sys
import glob
import json
import enum
import magic
import httpx
import typing
import shutil
import pathlib
import asyncio
import tarfile
import logging
import fastapi
import slowapi
import tempfile
import requests
import dataclasses
import collections
import generate_sarif

from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = fastapi.FastAPI()

#@app.get("/")
#async def redirect_to_docs():
#    return RedirectResponse(url="/docs/")

# docs
#app.mount("/docs", StaticFiles(directory="site", html=True), name="static")

# every client must have an approved bearer token to access
# locally deployed webservers are supported - no need for bearer tokens
EXPECTED_TOKEN = os.getenv('APPROVED_BEARER_TOKEN_0', '')

# every client must have an approved url to access
# (one url per client, which is also rate limited)
# locally deployed webservers are supported - no need for approved urls
NUM_APPROVED_URLS = os.getenv('NUM_APPROVED_URLS', '1')
APPROVED_URLS = [os.getenv(f'APPROVED_URL_{i}', 'scan') for i in range(int(NUM_APPROVED_URLS))]

limiter = slowapi.Limiter(key_func=lambda request: request.client.host)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s]: %(message)s",
    datefmt="%d/%m/%Y ( %H:%M:%S )",
    stream=sys.stdout
)

x = os.getenv('APPROVED_URL_0', '< undefined >')
logging.info(f'Approved url 0 = {x}')

# generate as many request handlers as needed
# each request handler listens to one approved url
# pylint: disable=cell-var-from-loop,redefined-outer-name
def create_handlers(approved_url: str):

    @app.post(f'/{approved_url}')
    @limiter.limit('60/minute')
    async def entrypoint(request: fastapi.Request, authorization: typing.Optional[str] = fastapi.Header(None)):
        return await scan(request, authorization)

for approved_url in APPROVED_URLS:
    create_handlers(approved_url)

class Language(str, enum.Enum):
    JS = 'js'
    TS = 'ts'
    TSX = 'tsx'
    PHP = 'php'
    PY = 'py'
    RB = 'rb'
    CS = 'cs'
    GO = 'go'
    BLADE_PHP = 'blade.php'

    @staticmethod
    def from_raw_str(raw: str) -> typing.Optional['Language']:
        try:
            return Language(raw)
        except ValueError:
            return None

AST_BUILDER_URL = {
    Language.JS: 'http://frontjs:3000/to/esprima/js/ast',
    Language.TS: 'http://frontts:3000/to/native/ts/ast',
    Language.TSX: 'http://frontts:3000/to/native/ts/ast',
    Language.PHP: 'http://frontphp:5000/to/php/ast',
    Language.PY: 'http://frontpy:5000/to/native/py/ast',
    Language.RB: 'http://frontrb:3000/to/native/cruby/ast',
    Language.CS: 'http://frontcs:8080/to/native/cs/ast',
    Language.GO: 'http://frontgo:8080/to/native/go/ast',
    Language.BLADE_PHP: 'http://frontphp:5000/to/php/code'
}

DHSCANNER_AST_BUILDER_URL = {
    Language.JS: 'http://parsers:3000/from/js/to/dhscanner/ast',
    Language.TS: 'http://parsers:3000/from/ts/to/dhscanner/ast',
    Language.TSX: 'http://parsers:3000/from/ts/to/dhscanner/ast',
    Language.PHP: 'http://parsers:3000/from/php/to/dhscanner/ast',
    Language.PY: 'http://parsers:3000/from/py/to/dhscanner/ast',
    Language.RB: 'http://parsers:3000/from/rb/to/dhscanner/ast',
    Language.CS: 'http://parsers:3000/from/cs/to/dhscanner/ast',
    Language.GO: 'http://parsers:3000/from/go/to/dhscanner/ast',
}

CSRF_TOKEN = 'http://frontphp:5000/csrf_token'

TO_CODEGEN_URL = 'http://codegen:3000/codegen'
TO_KBGEN_URL = 'http://kbgen:3000/kbgen'
TO_QUERY_ENGINE_URL = 'http://queryengine:5000/check'

# TODO: adjust other reasons for exclusion
# the reasons might depend on the language
# (like the third party directory name: node_module for javascript,
# site-packages for python or vendor/bundle for ruby etc.)
# pylint: disable=unused-argument
def scan_this_file(filename: str, language: Language, ignore_testing_code: bool = False) -> bool:
    if ignore_testing_code and '/test/' in filename:
        return False

    if ignore_testing_code and '.test.' in filename:
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

def compute_line_byte_offsets(code: str) -> dict[int, int]:
    offsets = {}
    current_offset = 0
    for i, line in enumerate(code.splitlines(keepends=True)):
        offsets[i + 1] = current_offset
        current_offset += len(line.encode('utf-8'))
    return offsets

def remove_tmp_prefix(filename: str) -> str:
    return re.sub(r"^/tmp/tmp[^/]+/", "", filename)

def read_single_file(filename: str, offsets: typing.Optional[dict[str, dict[int, int]]] = None):

    with open(filename, 'r', encoding='utf-8') as fl:
        code = fl.read()

    if offsets is not None:
        cleaned = remove_tmp_prefix(filename)
        offsets[cleaned] = compute_line_byte_offsets(code)

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

            # sometimes blade.php files are just plain php files
            # this could happen for various reasons ...
            # try the normal php parser first
            response = session.post(
                AST_BUILDER_URL[Language.PHP],
                files=just_one_blade_php_file,
                headers=headers,
                cookies=cookies
            )

            if response.ok:
                # no transformations need to be done
                # TODO: fix multiple sends of such blade.php files
                php_source_code = just_one_blade_php_file
            else:
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


def add_ast(filename: str, language: Language, asts: dict, offsets: dict[str, dict[int, int]]) -> None:

    one_file_at_a_time = read_single_file(filename, offsets)
    response = requests.post(AST_BUILDER_URL[language], files=one_file_at_a_time)
    asts[language].append({ 'filename': filename, 'actual_ast': response.text })

def parse_code(files: dict[Language, list[str]], offsets: dict[str, dict[int, int]]) -> dict[Language, list[dict[str, str]]]:

    asts = collections.defaultdict(list) # type: ignore[var-annotated]

    for language, filenames in files.items():
        if language not in [Language.PHP, Language.BLADE_PHP]:
            for filename in filenames:
                add_ast(filename, language, asts, offsets)

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

def parse_language_asts(language_asts):

    dhscanner_asts = collections.defaultdict(list)

    for language, asts in language_asts.items():
        for ast in asts:
            add_dhscanner_ast(ast['filename'], language, ast['actual_ast'], dhscanner_asts)

    return dhscanner_asts

def codegen(dhscanner_asts):

    callables = []
    for ast in dhscanner_asts:
        response = requests.post(TO_CODEGEN_URL, json=ast)
        more_callables = json.loads(response.text)['actualCallables']
        # logging.info(more_callables)
        callables.extend(more_callables)

    return callables

async def kbgen_single(client, one_callable):
    response = await client.post(TO_KBGEN_URL, json=one_callable)
    return response.text

async def kbgen_async(callables):
    async with httpx.AsyncClient() as client:
        tasks = [kbgen_single(client, c) for c in callables]
        responses = await asyncio.gather(*tasks)
    return responses

async def kbgen(callables):
    responses = await kbgen_async(callables)
    # logging.info(f'received {len(callables)} callables')
    return responses

# pylint: disable=consider-using-with,logging-fstring-interpolation
def query_engine(kb_filename: str, queries_filename: str, debug: bool) -> str:

    kb_and_queries = {
        'kb': ('kb', open(kb_filename, encoding='utf-8')),
        'queries': ('queries', open(queries_filename, encoding='utf-8')),
    }

    url = f'{TO_QUERY_ENGINE_URL}'
    response = requests.post(url, files=kb_and_queries, data={'debug': json.dumps(debug)})
    return response.text

def patternify(suffix: str) -> str:
    start = r'startloc_(\d+)_(\d+)'
    end = r'endloc_(\d+)_(\d+)'
    fname = fr'([^,]+_dot_{suffix})'
    loc = fr'{start}_{end}_{fname}'
    edge = fr'\({loc},{loc}\)'
    path = fr'{edge}(,{edge})*'
    query = r'q(\d+)'
    return fr'{query}\(\[{path}\]\): yes'

def sinkify(match: re.Match, filename: str, offsets: dict[str, dict[int, int]]) -> typing.Optional[generate_sarif.Region]:

    n = len(match.groups())
    for i in reversed(range(5, n)):

        try:
            locs = [int(match.group(i-d)) for d in reversed(range(4))]
        except (ValueError, TypeError):
            continue

        return generate_sarif.Region(
            startLine=locs[0],
            startColumn=normalize(filename, locs[0], locs[1], offsets),
            endLine=locs[2],
            endColumn=normalize(filename, locs[2], locs[3], offsets)
        )

    return None

@dataclasses.dataclass(kw_only=True, frozen=True)
class Location:

    filename: str
    lineStart: int
    lineEnd: int
    colStart: int
    colEnd: int

    def __str__(self) -> str:
        return f'[{self.lineStart}:{self.colStart}-{self.lineEnd}:{self.colEnd}]'

    @staticmethod
    def from_dict(candidate: dict) -> typing.Optional['Location']:

        if 'filename' not in candidate:
            return None
        if 'lineStart' not in candidate:
            return None
        if 'lineEnd' not in candidate:
            return None
        if 'colStart' not in candidate:
            return None
        if 'colEnd' not in candidate:
            return None

        return Location(
            filename=remove_tmp_prefix(candidate['filename']),
            lineStart=candidate['lineStart'],
            lineEnd=candidate['lineEnd'],
            colStart=candidate['colStart'],
            colEnd=candidate['colEnd']
        )

def restore(filename: str) -> str:
    return filename.replace('_slash_', '/').replace('_dot_', '.').replace('_dash_', '-')

def normalize(filename: str, line: int, offset: int, offsets) -> int:
    if filename in offsets:
        if line in offsets[filename]:
            if offset >= offsets[filename][line]:
                return offset - offsets[filename][line] + 1

    return offset

# pylint: disable=too-many-locals,too-many-branches,too-many-statements,logging-fstring-interpolation
async def scan(request: fastapi.Request, authorization: typing.Optional[str] = fastapi.Header(None)) -> dict:

    code_sent_to_external_server = request.headers.get(
        'X-Code-Sent-To-External-Server', 'true'
    )

    external_server_involved = code_sent_to_external_server in [ 'true' ]
    if external_server_involved:
        logging.info('[ step 0 ] external server involved ⚠️')
        logging.info('[ step 0 ] external server involved use an approved bearer token')
        logging.info('[ step 0 ] external server involved use an approved url')
    else:
        logging.info('[ step 0 ] external server used   : no  😃')
        logging.info('[ step 0 ] approved bearer token  : no need 😉')
        logging.info('[ step 0 ] approved url           : no need 😉')

    if external_server_involved and authorization is None:
        raise fastapi.HTTPException(
            status_code=401,
            detail='Missing authorization header'
        )

    if authorization is not None:
        logging.info('[ step 1 ] authorization headers  : yes 😃 ')

    if external_server_involved:
        if authorization is not None:
            if not authorization.startswith('Bearer '):
                raise fastapi.HTTPException(
                    status_code=401,
                    detail='Invalid authorization header'
                )

    if external_server_involved:
        if authorization is not None:
            if authorization.startswith('Bearer '):
                token = authorization[len('Bearer '):]
                if token != EXPECTED_TOKEN:
                    raise fastapi.HTTPException(
                        status_code=403,
                        detail="Invalid Bearer token"
                    )

                logging.info('[ step 1 ] bearer token sent .... : yes 😃 ')
                logging.info('[ step 1 ] bearer token valid ... : yes 😃 ')


    content_type = request.headers.get("content-type")
    if content_type != "application/octet-stream":
        raise fastapi.HTTPException(
            status_code=400,
            detail="Invalid content type"
        )

    logging.info('[ step 1 ] streamed tar file .... : yes 😃 ')

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

    ignore_testing_code_str = request.headers.get('X-Ignore-Testing-Code', 'false').lower()
    ignore_testing_code = (ignore_testing_code_str in ['yes', 'true'])

    files = collect_all_sources(workdir, ignore_testing_code)

    logging.info('[ step 2 ] native asts .......... : started  😃 ')

    offsets: dict[str, dict[int, int]] = {}
    language_asts = parse_code(files, offsets)

    if native_ast_filename := request.headers.get('X-Show-Native-Ast-For-File', None):
        l = pathlib.Path(native_ast_filename).suffix.lstrip('.')
        lang = Language.from_raw_str(l)
        if lang and lang in language_asts:
            asts = language_asts[lang]
            for ast in asts:
                if 'filename' in ast:
                    candidate = remove_tmp_prefix(ast['filename'])
                    if native_ast_filename == candidate:
                        content = ast['actual_ast']
                        logging.info(f'[ step 2 ] native ast of: {native_ast_filename}')
                        logging.info(f'[ step 2 ] {content}')

    logging.info('[ step 2 ] native asts .......... : finished 😃 ')

    # before the entire working directory is deleted,
    # make sure to copy the queries file ( if it exists )
    with tempfile.NamedTemporaryFile(delete=False) as queries_file:
        queries_filename = queries_file.name
        dhscanner_queries = os.path.join(workdir, '.dhscanner.queries')
        if pathlib.Path(dhscanner_queries).is_file():
            shutil.copy(dhscanner_queries, queries_filename)
        else:
            # resort to the default of checking owasp top 10
            # see: https://owasp.org/www-project-top-ten/
            with open(queries_filename, 'w', encoding='utf-8') as fl:
                fl.write('problems().')

    # actual source files are no longer needed
    # everything is inside the language asts
    # .dhscanner.queries was copied to another location
    shutil.rmtree(workdir)

    logging.info('[ step 2 ] deleting all src files : finished 😃 ')

    dhscanner_asts = parse_language_asts(language_asts)

    valid_dhscanner_asts = []
    total_num_files: dict[Language, int] = collections.defaultdict(int)
    num_parse_errors: dict[Language, int] = collections.defaultdict(int)

    locations: dict[str, Location] = {}

    for language, asts in dhscanner_asts.items():
        for ast in asts:
            try:
                result = json.loads(ast['dhscanner_ast'])
                if 'status' in result and 'location' in result and result['status'] == 'FAILED':
                    num_parse_errors[language] += 1
                    total_num_files[language] += 1
                    if loc := Location.from_dict(result['location']):
                        locations[loc.filename] = loc
                    continue

            except ValueError:
                continue

            valid_dhscanner_asts.append(result)
            total_num_files[language] += 1

    for language in dhscanner_asts.keys():
        n = total_num_files[language]
        errors = num_parse_errors[language]
        logging.info(f'[ step 2 ] dhscanner ast ( {language.value:<3} )  : {n - errors}/{n}')

    if parse_status_filename := request.headers.get('X-Show-Parse-Status-For-File', None):
        logging.info(f'[ step 2 ] parse info: {parse_status_filename}')
        if parse_status_filename in locations:
            logging.info(f'[ step 2 ] parser error loc: {str(locations[parse_status_filename])}')

    logging.info('[ step 2 ] dhscanner asts ....... : finished 😃 ')
    logging.info('[ step 3 ] code gen ............. : started  😃 ')

    callables = codegen(valid_dhscanner_asts)

    logging.info('[ step 3 ] code gen ............. : finished 😃 ')
    logging.info('[ step 4 ] knowledge base gen ... : started  😃 ')

    facts = []
    # callables = bitcode_as_json['actualCallables']
    n = len(callables)
    logging.info(f'[ step 4 ] callables ............ : {n}')
    for index, one_callable in enumerate(callables):
        response = requests.post(TO_KBGEN_URL, json=one_callable)
        # logging.info(response.text)
        more_facts = json.loads(response.text)['content']
        new_facts = len(more_facts)
        facts.extend(more_facts)
        logging.info(f'[ step 4 ] {new_facts:<3} facts {index:<3}/{n:<3} :')

    with tempfile.NamedTemporaryFile(suffix=".pl", mode='w', delete=False) as f:
        kb_filename = f.name
        dummy_classloc = 'not_a_real_loc'
        dummy_classname = "'not_a_real_classname'"
        dummy_callable = 'not_a_real_callable'
        dummy_annotation = "'not.a.real.fqn'"
        dummy_param_name = "'not_a_real_param_name'"
        dummy_param = 'not_a_real_param'
        f.write(f'kb_class_name({dummy_classloc},{dummy_classname}).\n')
        f.write(f'kb_subclass_of({dummy_classloc},{dummy_classname}).\n')
        f.write(f'kb_callable_has_param({dummy_callable},{dummy_param}).\n')
        f.write(f'kb_callable_annotated_with({dummy_callable},{dummy_annotation}).\n')
        f.write(f'kb_callable_annotated_with_user_input_inside_route({dummy_callable},{dummy_param_name}).\n')
        f.write('\n'.join(sorted(set(facts))))
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

    logging.info('[ step 7 ] deleted query file ... : finished 😃 ')
    logging.info(result)

    sarif = generate_sarif.empty()
    for language in Language:
        suffix = language.value
        pattern = patternify(suffix)
        if match := re.search(pattern, result):
            # TODO: propagate the query number inside the Sarif output
            query_number = int(match.group(1)) # pylint: disable=unused-variable
            lineStart = int(match.group(2))
            colStart = int(match.group(3))
            lineEnd = int(match.group(4))
            colEnd = int(match.group(5))
            filename_start_instrumented = match.group(6)
            filename_start = restore(filename_start_instrumented)

            source = generate_sarif.Region(
                startLine=lineStart,
                endLine=lineEnd,
                startColumn=normalize(filename_start, lineStart, colStart, offsets),
                endColumn=normalize(filename_start, lineEnd, colEnd, offsets)
            )

            filename_end_instrumented = match.group(len(match.groups()))
            filename_end = restore(filename_end_instrumented)

            sink = sinkify(match, filename_end, offsets)
            if sink is None:
                sink = source

            sarif = generate_sarif.run(
                filename_start=filename_start,
                filename_end=filename_end,
                description='owasp top 10',
                start=source,
                end=sink
            )

            # TODO: find *all* paths, rather than stopping
            # after the first path found
            break

    logging.info('[ step 8 ] sarif response ....... : finished 😃 ')
    logging.info('[ step 9 ] sending response now   :  🚀 ')

    return dataclasses.asdict(sarif)
