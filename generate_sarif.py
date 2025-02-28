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

    lineStart: int
    lineEnd: int
    colStart: int
    colEnd: int

    @staticmethod
    def make_default() -> Region:
        return Region(
            lineStart=0,
            lineEnd=0,
            colStart=0,
            colEnd=0
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

    runs: list[SarifRun]

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
    return Sarif(runs)
