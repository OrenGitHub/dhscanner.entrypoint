from __future__ import annotations

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

    @staticmethod
    def make_default() -> Region:
        return Region(
            startLine=0,
            endLine=0,
            startColumn=0,
            endColumn=0
        )

@dataclasses.dataclass(frozen=True)
class ArtifactLocation:

    uri: str

@dataclasses.dataclass(frozen=True)
class PhysicalLocation:

    artifactLocation: ArtifactLocation
    region: Region

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

    version: str
    runs: list[SarifRun]

def empty() -> Sarif:
    driver = Driver('dhscanner')
    dhscanner = SarifTool(driver)
    runs = [SarifRun(tool=dhscanner,results=[])]
    return Sarif('2.1.0', runs)

def run(filename: str, description: str, region: Region) -> Sarif:
    driver = Driver('dhscanner')
    dhscanner = SarifTool(driver)
    artifactLocation = ArtifactLocation(filename)
    physical_location = PhysicalLocation(artifactLocation, region)
    location = SarifLocation(physical_location)
    result = SarifResult(
        ruleId='dataflow',
        message=SarifMessage(description),
        locations=[location]
    )
    runs = [SarifRun(tool=dhscanner,results=[result])]
    return Sarif('2.1.0', runs)
