import dataclasses

@dataclasses.dataclass(frozen=True)
class Driver:

    name: str

@dataclasses.dataclass(frozen=True)
class SarifMessage:

    text: str

@dataclasses.dataclass(frozen=True, kw_only=True)
class Region:

    startLine: int
    endLine: int
    startColumn: int
    endColumn: int

@dataclasses.dataclass(frozen=True)
class ArtifactLocation:

    uri: str

@dataclasses.dataclass(frozen=True)
class PhysicalLocation:

    artifactLocation: ArtifactLocation
    resgion: Region

@dataclasses.dataclass(frozen=True)
class SarifLocation:

    physicalLocation: PhysicalLocation

@dataclasses.dataclass(frozen=True, kw_only=True)
class SarifResult:

    ruleId: str
    message: SarifMessage
    locations: list[SarifLocation]

@dataclasses.dataclass(frozen=True)
class SarifTool:

    driver: Driver

@dataclasses.dataclass(frozen=True, kw_only=True)
class SarifRun:

    tool: SarifTool
    results: list[SarifResult]

@dataclasses.dataclass(frozen=True)
class Sarif:

    runs: list[SarifRun]

def run(filename: str, description: str) -> Sarif:
    driver = Driver('dhscanner')
    dhscanner = SarifTool(driver)
    region = Region(
        startLine=7,
        endLine=9,
        startColumn=511,
        endColumn=589
    )
    artifactLocation = ArtifactLocation(filename)
    physical_location = PhysicalLocation(artifactLocation, region)
    location = SarifLocation(physical_location)
    result = SarifResult(
        ruleId='dataflow',
        message=SarifMessage(description),
        locations=[location]
    )
    runs = [SarifRun(tool=dhscanner,results=[result])]
    return Sarif(runs)
