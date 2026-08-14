// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DIDRegistry
/// @notice 将 DID 注册到链上，记录其控制者地址，支持解析、转移控制权与注销
contract DIDRegistry {
    /// @notice DID → 控制者地址
    mapping(string => address) public didToController;

    /// @notice 控制者地址 → 其拥有的 DID 列表
    mapping(address => string[]) private _controllerDids;

    event DIDRegistered(string indexed did, address indexed controller);
    event DIDTransfered(string indexed did, address indexed oldController, address indexed newController);
    event DIDDeactivated(string indexed did, address indexed controller);

    error EmptyDID();
    error DIDAlreadyExists(string did);
    error DIDNotFound(string did);
    error NotController(string did, address caller);

    /// @notice 注册一个新的 DID，调用者成为其控制者
    function registerDID(string calldata did) external {
        if (bytes(did).length == 0) revert EmptyDID();
        if (didToController[did] != address(0)) revert DIDAlreadyExists(did);

        didToController[did] = msg.sender;
        _controllerDids[msg.sender].push(did);

        emit DIDRegistered(did, msg.sender);
    }

    /// @notice 解析 DID，返回其控制者地址
    function resolveDID(string calldata did) external view returns (address) {
        address controller = didToController[did];
        if (controller == address(0)) revert DIDNotFound(did);
        return controller;
    }

    /// @notice 将 DID 的控制权转移给新控制者
    function transferControl(string calldata did, address newController) external {
        address controller = didToController[did];
        if (controller == address(0)) revert DIDNotFound(did);
        if (controller != msg.sender) revert NotController(did, msg.sender);
        if (newController == address(0)) revert DIDNotFound(did);

        didToController[did] = newController;
        _removeDidFromController(did, controller);
        _controllerDids[newController].push(did);

        emit DIDTransfered(did, controller, newController);
    }

    /// @notice 注销 DID（从链上移除控制者映射）
    function deactivateDID(string calldata did) external {
        address controller = didToController[did];
        if (controller == address(0)) revert DIDNotFound(did);
        if (controller != msg.sender) revert NotController(did, msg.sender);

        delete didToController[did];
        _removeDidFromController(did, controller);

        emit DIDDeactivated(did, controller);
    }

    /// @notice 查询某地址控制的全部 DID
    function getDIDsByController(address controller) external view returns (string[] memory) {
        return _controllerDids[controller];
    }

    function _removeDidFromController(string memory did, address controller) private {
        string[] storage dids = _controllerDids[controller];
        for (uint256 i = 0; i < dids.length; i++) {
            if (keccak256(bytes(dids[i])) == keccak256(bytes(did))) {
                dids[i] = dids[dids.length - 1];
                dids.pop();
                break;
            }
        }
    }
}
