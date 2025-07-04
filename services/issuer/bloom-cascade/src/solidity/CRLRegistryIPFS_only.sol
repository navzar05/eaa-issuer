// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract CRLRegistry {
    struct CRL {
        string cid;
        uint256 expiresAt;
        uint256 version;
    }

    mapping(address => CRL) public crls;
    mapping(address => bool) public issuers;

    string public constant NAME = "CRL Registry IPFS Only";
    string public constant VERSION = "1.0.0";

    event CRLPublished(
        address indexed issuer,
        string cid,
        uint256 expiresAt,
        uint256 version
    );

    function publishCRL(
        string memory cid,
        uint256 validityHours
    ) external {
        require(bytes(cid).length > 0, "Cid cannot be empty");
        require(validityHours > 0 && validityHours <= 168, "Invalid validity");

        address issuer = msg.sender;
        uint256 expiresAt = block.timestamp + (validityHours * 3600);
        
        uint256 newVersion = crls[issuer].version + 1;

        crls[issuer]= CRL({
            cid: cid,
            expiresAt: expiresAt,
            version: newVersion
        });

        if (!issuers[issuer]) {
            issuers[issuer] = true;
        }

        emit CRLPublished(issuer, cid, expiresAt, newVersion);
    }

    function getCRL(address issuer)
        external
        view
        returns (
            string memory cid,
            uint256 expiresAt,
            uint256 version,
            bool isValid
        )
    {
        require(issuers[issuer], "Issuer not found");

        CRL memory crl = crls[issuer];
        require(crl.version > 0, "No CRL found for this save method");
        
        bool valid = block.timestamp < crl.expiresAt;

        return (crl.cid, crl.expiresAt, crl.version, valid);
    }
}