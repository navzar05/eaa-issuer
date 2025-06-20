// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract CRLRegistry {
    enum SaveMethod {
        BLOB,
        IPFS
    }

    struct CRL {
        SaveMethod saveMethod;
        string pointerHash;
        uint256 expiresAt;
        uint256 version;
    }

    mapping(address => mapping(SaveMethod => CRL)) public crls;
    mapping(address => bool) public issuers;

    string public constant NAME = "CRL Registry";
    string public constant VERSION = "1.0.0";

    event CRLPublished(
        address indexed issuer,
        SaveMethod indexed saveMethod,
        string pointerHash,
        uint256 expiresAt,
        uint256 version
    );

    function publishCRL(
        SaveMethod saveMethod,
        string memory pointerHash,
        uint256 validityHours
    ) external {
        require(bytes(pointerHash).length > 0, "Pointer hash cannot be empty");
        require(validityHours > 0 && validityHours <= 168, "Invalid validity");

        address issuer = msg.sender;
        uint256 expiresAt = block.timestamp + (validityHours * 3600);
        
        uint256 newVersion = crls[issuer][saveMethod].version + 1;

        crls[issuer][saveMethod] = CRL({
            saveMethod: saveMethod,
            pointerHash: pointerHash,
            expiresAt: expiresAt,
            version: newVersion
        });

        if (!issuers[issuer]) {
            issuers[issuer] = true;
        }

        emit CRLPublished(issuer, saveMethod, pointerHash, expiresAt, newVersion);
    }

    function getCRL(address issuer, SaveMethod saveMethod)
        external
        view
        returns (
            string memory pointerHash,
            uint256 expiresAt,
            uint256 version,
            bool isValid
        )
    {
        require(issuers[issuer], "Issuer not found");

        CRL memory crl = crls[issuer][saveMethod];
        require(crl.version > 0, "No CRL found for this save method");
        
        bool valid = block.timestamp < crl.expiresAt;

        return (crl.pointerHash, crl.expiresAt, crl.version, valid);
    }
}