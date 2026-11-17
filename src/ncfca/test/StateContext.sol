// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract StateContext {
    address public immutable oracleUpdater;

    struct MarketObservation {
        uint256 referencePriceE18; // TokenOut per TokenIn scaled by 1e18
        uint256 observedAt;        // Freshness timestamp
        bytes32 sourceId;          // Provenance identifier
    }

    mapping(bytes32 => MarketObservation) private _observations;

    event ObservationRecorded(bytes32 indexed pairId, uint256 priceE18, uint256 timestamp, bytes32 sourceId);

    error UnauthorizedOracle(address caller);

    constructor(address _oracleUpdater) {
        oracleUpdater = _oracleUpdater;
    }

    function recordObservation(
        address tokenIn,
        address tokenOut,
        uint256 referencePriceE18,
        bytes32 sourceId
    ) external {
        if (msg.sender != oracleUpdater) {
            revert UnauthorizedOracle(msg.sender);
        }
        bytes32 pairId = keccak256(abi.encodePacked(tokenIn, tokenOut));
        _observations[pairId] = MarketObservation({
            referencePriceE18: referencePriceE18,
            observedAt: block.timestamp,
            sourceId: sourceId
        });

        emit ObservationRecorded(pairId, referencePriceE18, block.timestamp, sourceId);
    }

    function getObservation(address tokenIn, address tokenOut) external view returns (MarketObservation memory) {
        return _observations[keccak256(abi.encodePacked(tokenIn, tokenOut))];
    }
}
