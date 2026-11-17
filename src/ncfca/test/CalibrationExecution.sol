// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBreakerTrigger {
    function recordAnomalyObservation(uint256 anomalyIndex) external;
}

/// @title CalibrationExecution (C-Channel Profile — Document 07, Section 6.4)
/// @notice Append-only telemetry logger. Computes execution anomaly index A_C(t) and notifies CircuitBreaker.
/// @dev Holds ZERO write authority over DynamicState (D).
contract CalibrationExecution {
    address public immutable swapExecutor;
    IBreakerTrigger public immutable circuitBreaker;

    struct ExecutionTrace {
        bytes32 requestDigest;
        uint256 expectedOut;
        uint256 actualOut;
        uint256 deviationBps;
        uint256 gasUsed;
        uint256 timestamp;
    }

    ExecutionTrace[] private _traces;

    event TelemetryLogged(uint256 indexed traceId, bytes32 indexed requestDigest, uint256 deviationBps, uint256 gasUsed);

    error UnauthorizedExecutor(address caller);

    constructor(address _swapExecutor, address _circuitBreaker) {
        swapExecutor = _swapExecutor;
        circuitBreaker = IBreakerTrigger(_circuitBreaker);
    }

    function recordExecution(
        bytes32 requestDigest,
        uint256 expectedOut,
        uint256 actualOut,
        uint256 gasUsed
    ) external {
        if (msg.sender != swapExecutor) {
            revert UnauthorizedExecutor(msg.sender);
        }

        uint256 deviationBps = 0;
        if (expectedOut > actualOut) {
            deviationBps = ((expectedOut - actualOut) * 10_000) / expectedOut;
        }

        _traces.push(
            ExecutionTrace({
                requestDigest: requestDigest,
                expectedOut: expectedOut,
                actualOut: actualOut,
                deviationBps: deviationBps,
                gasUsed: gasUsed,
                timestamp: block.timestamp
            })
        );

        emit TelemetryLogged(_traces.length - 1, requestDigest, deviationBps, gasUsed);

        // Feed continuous anomaly index A_C(t) (measured in slippage deviation bps) to CircuitBreaker
        circuitBreaker.recordAnomalyObservation(deviationBps);
    }

    function traceCount() external view returns (uint256) {
        return _traces.length;
    }

    function getTrace(uint256 index) external view returns (ExecutionTrace memory) {
        return _traces[index];
    }
}
