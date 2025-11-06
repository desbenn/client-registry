// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "lib/openzeppelin-contracts/contracts/access/AccessControl.sol";

// cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 "isClientActive(address)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url http://127.0.0.1:8545

contract ClientRegistry is AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    struct Record {
        address issuer;
        uint256 timestamp;
        bytes32 dataHash;
        bool revoked;
    }

    // client address => array of records
    mapping(address => Record[]) private _records;

    event ClientRegistered(
        address indexed client,
        address indexed issuer,
        bytes32 dataHash,
        uint256 timestamp
    );
    event ClientRevoked(
        address indexed client,
        address indexed issuer,
        bytes32 dataHash,
        uint256 timestamp
    );

    constructor(address admin) {
        // Grant admin the default admin role and issuer/revoker roles initially
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_ROLE, admin);
        _grantRole(REVOKER_ROLE, admin);
    }

    modifier onlyIssuer() {
        require(
            hasRole(ISSUER_ROLE, msg.sender),
            "ClientRegistry: caller is not an issuer"
        );
        _;
    }

    modifier onlyRevoker() {
        require(
            hasRole(REVOKER_ROLE, msg.sender),
            "ClientRegistry: caller is not a revoker"
        );
        _;
    }

    /// @notice Register (add) a verification record for a client. Stores only a data hash.
    /// @param client The client address the record is about
    /// @param dataHash keccak256 hash of the off-chain verification payload
    function registerClient(
        address client,
        bytes32 dataHash
    ) external onlyIssuer {
        require(client != address(0), "ClientRegistry: client is zero address");
        Record memory r = Record({
            issuer: msg.sender,
            timestamp: block.timestamp,
            dataHash: dataHash,
            revoked: false
        });
        _records[client].push(r);
        emit ClientRegistered(client, msg.sender, dataHash, block.timestamp);
    }

    /// @notice Revoke the latest record for a client. Keeps historical records but marks latest as revoked.
    /// @param client The client address
    function revokeLatest(
        address client,
        bytes32 dataHash
    ) external onlyRevoker {
        uint256 len = _records[client].length;
        require(len > 0, "ClientRegistry: no records");
        Record storage latest = _records[client][len - 1];
        require(
            latest.dataHash == dataHash,
            "ClientRegistry: dataHash mismatch"
        );
        latest.revoked = true;
        emit ClientRevoked(client, msg.sender, dataHash, block.timestamp);
    }

    /// @notice Return the number of records for a client
    function recordCount(address client) external view returns (uint256) {
        return _records[client].length;
    }

    /// @notice Return the latest record for a client
    function latestRecord(
        address client
    )
        external
        view
        returns (
            address issuer,
            uint256 timestamp,
            bytes32 dataHash,
            bool revoked
        )
    {
        uint256 len = _records[client].length;
        require(len > 0, "ClientRegistry: no records");
        Record storage r = _records[client][len - 1];
        return (r.issuer, r.timestamp, r.dataHash, r.revoked);
    }

    /// @notice Return a record by index (0-based, 0 is oldest)
    function recordAt(
        address client,
        uint256 index
    )
        external
        view
        returns (
            address issuer,
            uint256 timestamp,
            bytes32 dataHash,
            bool revoked
        )
    {
        require(index < _records[client].length, "ClientRegistry: index OOB");
        Record storage r = _records[client][index];
        return (r.issuer, r.timestamp, r.dataHash, r.revoked);
    }
}
