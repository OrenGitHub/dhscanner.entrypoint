from __future__ import annotations

import typing
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

@dataclasses.dataclass(frozen=True)
class ThreadFlowLocation:

    location: SarifLocation

@dataclasses.dataclass(frozen=True)
class ThreadFlow:

    locations: list[ThreadFlowLocation]

@dataclasses.dataclass(frozen=True)
class CodeFlow:

    threadFlows: list[ThreadFlow]

@dataclasses.dataclass(frozen=True, kw_only=True)
class SarifResult:

    ruleId: str
    message: SarifMessage
    locations: list[SarifLocation]
    codeFlows: typing.Optional[list[CodeFlow]]

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

# pylint: disable=too-many-locals
def run(*, filename_start: str, filename_end: str, description: str, start: Region, end: Region) -> Sarif:
    driver = Driver('dhscanner')
    dhscanner = SarifTool(driver)
    artifactLocation_start = ArtifactLocation(filename_start)
    artifactLocation_end = ArtifactLocation(filename_end)
    sarif_location_start = SarifLocation(PhysicalLocation(artifactLocation_start, start))
    sarif_location_end = SarifLocation(PhysicalLocation(artifactLocation_end, end))
    thread_flow_start = ThreadFlowLocation(sarif_location_start)
    thread_flow_end = ThreadFlowLocation(sarif_location_end)
    thread_flow = [ThreadFlow([thread_flow_start, thread_flow_end])]
    codeFlows = [CodeFlow(thread_flow)]
    result = SarifResult(
        ruleId='dataflow',
        message=SarifMessage(description),
        locations=[sarif_location_end],
        codeFlows=codeFlows

    )
    runs = [SarifRun(tool=dhscanner,results=[result])]
    return Sarif('2.1.0', runs)
