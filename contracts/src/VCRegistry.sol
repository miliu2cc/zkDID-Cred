// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VCRegistry
/// @notice 凭证哈希上链（防篡改时间戳）与撤销列表管理
contract VCRegistry {
    struct CredentialRecord {
        address issuer;
        string subjectDid;
        uint256 registeredAt;
        bool exists;
        bool revoked;
    }

    mapping(bytes32 => CredentialRecord) private _records;

    event CredentialRegistered(bytes32 indexed hash, address indexed issuer, string subjectDid, uint256 timestamp);
    event CredentialRevoked(bytes32 indexed hash, address indexed issuer);

    error CredentialAlreadyExists(bytes32 hash);
    error CredentialNotFound(bytes32 hash);
    error AlreadyRevoked(bytes32 hash);
    error NotIssuer(bytes32 hash, address caller);

    /// @notice 注册凭证哈希（防篡改时间戳），记录签发方与主体 DID
    function registerCredential(bytes32 hash, string calldata subjectDid) external {
        if (_records[hash].exists) revert CredentialAlreadyExists(hash);

        _records[hash] = CredentialRecord({
            issuer: msg.sender,
            subjectDid: subjectDid,
            registeredAt: block.timestamp,
            exists: true,
            revoked: false
        });

        emit CredentialRegistered(hash, msg.sender, subjectDid, block.timestamp);
    }

    /// @notice 撤销凭证（仅签发方可撤销）
    function revokeCredential(bytes32 hash) external {
        CredentialRecord storage record = _records[hash];
        if (!record.exists) revert CredentialNotFound(hash);
        if (record.issuer != msg.sender) revert NotIssuer(hash, msg.sender);
        if (record.revoked) revert AlreadyRevoked(hash);

        record.revoked = true;
        emit CredentialRevoked(hash, msg.sender);
    }

    /// @notice 查询凭证是否已被撤销
    function isRevoked(bytes32 hash) external view returns (bool) {
        return _records[hash].revoked;
    }

    /// @notice 查询凭证完整记录
    function getCredential(bytes32 hash)
        external
        view
        returns (address issuer, string memory subjectDid, uint256 registeredAt, bool exists, bool revoked)
    {
        CredentialRecord storage record = _records[hash];
        return (record.issuer, record.subjectDid, record.registeredAt, record.exists, record.revoked);
    }
}
