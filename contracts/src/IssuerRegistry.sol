// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IssuerRegistry
/// @notice 学校（签发方）白名单管理，只有白名单内的机构才有权签发凭证
contract IssuerRegistry {
    address public owner;

    mapping(address => bool) public isIssuer;
    mapping(address => string) public issuerName;
    address[] private _issuers;

    event IssuerAdded(address indexed issuer, string name);
    event IssuerRemoved(address indexed issuer);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    error NotOwner(address caller);
    error AlreadyIssuer(address issuer);
    error NotIssuer(address issuer);
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice 添加一个授权签发方（学校）
    function addIssuer(address issuer, string calldata name) external onlyOwner {
        if (issuer == address(0)) revert ZeroAddress();
        if (isIssuer[issuer]) revert AlreadyIssuer(issuer);

        isIssuer[issuer] = true;
        issuerName[issuer] = name;
        _issuers.push(issuer);

        emit IssuerAdded(issuer, name);
    }

    /// @notice 移除一个签发方
    function removeIssuer(address issuer) external onlyOwner {
        if (!isIssuer[issuer]) revert NotIssuer(issuer);

        isIssuer[issuer] = false;
        delete issuerName[issuer];
        _removeFromList(issuer);

        emit IssuerRemoved(issuer);
    }

    /// @notice 查询某地址是否为授权签发方
    function isAuthorized(address issuer) external view returns (bool) {
        return isIssuer[issuer];
    }

    /// @notice 当前授权签发方数量
    function getIssuerCount() external view returns (uint256) {
        return _issuers.length;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    function _removeFromList(address issuer) private {
        for (uint256 i = 0; i < _issuers.length; i++) {
            if (_issuers[i] == issuer) {
                _issuers[i] = _issuers[_issuers.length - 1];
                _issuers.pop();
                break;
            }
        }
    }
}
