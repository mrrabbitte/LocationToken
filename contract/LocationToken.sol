// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LocationToken {

    // both latitude and longitude have scale parameter
    // a) real_lat = lat / scale_lat
    // b) real_lon = lon / scale_lon
    struct Location {
        uint32 scale_lat;
        uint64 lat; // whole number of the real latitude * scale_lat
        uint32 scale_lon;
        uint64 lon; // whole number of the real longitude * scale_lon
    }

    struct Challenger {
        string id;
        address rewardsAddr;
        bytes pubKey;
        bytes checksum;
        string wifiNetwork;
        Location location;
        bool isBlocklisted;
        bool exists;
    }

    struct Traveller {
        string id;
        bytes pubKey;
        bytes checksum;
        bool isBlocklisted;
        bool exists;
    }

    struct ProofOfLocation {
        uint256 fastId;
        string travellerId;
        string challengerId;
        string nonce_c;
        uint64 created_at;
        uint64 ttl;
        bytes c_signature;
        bytes t_signature;
        bytes proof;
        bool exists;
    }

    address public owner;

    // Fees for the DAO services
    uint256 public travellerRegistrationFee;
    uint128 public challengerRegistrationFee;
    uint128 public proofOfLocationRegistrationFee;

    // Rewards for network contributions
    uint256 public proofChallengerReward;
    mapping(uint256 => uint128) public rewardsByChallenger;
    uint256 public totalRewards;

    // Dao core business value
    mapping(uint256 => Challenger) public challengers;
    mapping(uint256 => Traveller) public travellers;
    mapping(uint256 => ProofOfLocation) public proofs;
    mapping(string => Challenger) public wifiNameToChallenger;

    // Events
    event ProofOfLocationSubmitted(
        string indexed travellerId,
        string indexed challengerId,
        uint256 indexed proofId
    );
    event ChallengerRegistered(string indexed challengerId, Location location, string wifiNetwork);
    event TravellerBlocklisted(string indexed travellerId);
    event ChallengerBlocklisted(string indexed challengerId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this action");
        _;
    }

    modifier travellerOk(string memory travellerId) {
        uint256 internalId = toInternalId(travellerId);
        require(!travellers[internalId].isBlocklisted, "You are blocklisted");
        _;
    }

    modifier travellerExists(string memory travellerId) {
        uint256 internalId = toInternalId(travellerId);
        require(travellers[internalId].exists, "Traveller does not exist");
        _;
    }

    modifier challengerOk(string memory challengerId) {
        uint256 internalId = toInternalId(challengerId);
        require(!challengers[internalId].isBlocklisted, "You are blocklisted");
        _;
    }

    modifier challengerExists(string memory challengerId) {
        uint256 internalId = toInternalId(challengerId);
        require(challengers[internalId].exists, "Challenger does not exist");
        _;
    }


    constructor() {
        owner = msg.sender;
        challengerRegistrationFee = 0.0001 ether;
        travellerRegistrationFee = 0.0001 ether;
        proofOfLocationRegistrationFee = 0.0001 ether;
    }

    function registerChallenger(
        string memory challengerId,
        address rewardsAddr,
        bytes memory challengerPubKey,
        bytes memory challengerChecksum,
        string memory wifiNetwork,
        uint32 scaleLat,
        uint64 lat,
        uint32 scaleLon,
        uint64 lon) challengerOk(challengerId) external payable {
        require(msg.value >= challengerRegistrationFee, "Insufficient fee to register the challenger");

        uint256 internalId = toInternalId(challengerId);

        require(!challengers[internalId].exists, "Challenger is already registered.");

        Location memory location = Location(scaleLat, lat, scaleLon, lon);

        challengers[internalId] = Challenger(
            challengerId,
            rewardsAddr,
            challengerPubKey,
            challengerChecksum,
            wifiNetwork,
            location,
            false,
            true);
        rewardsByChallenger[internalId] = 0;

        emit ChallengerRegistered(challengerId, location, wifiNetwork);
    }


    function registerTraveller(
        string memory travellerId,
        bytes memory travellerPubKey,
        bytes memory travellerChecksum) travellerOk(travellerId) external payable {
        require(msg.value >= challengerRegistrationFee, "Insufficient fee to register the traveller");

        uint256 internalId = toInternalId(travellerId);

        require(!travellers[internalId].exists, "Traveller is already registered.");

        travellers[internalId] = Traveller(
            travellerId,
            travellerPubKey,
            travellerChecksum,
            false,
            true);
    }

    event DebugBytes32(string label, bytes32 value);

    function registerLocationProof(
        string memory travellerId,
        string memory challengerId,
        string memory nonce_c,
        uint64 created_at,
        uint64 ttl,
        bytes memory c_signature,
        bytes memory t_signature,
        bytes memory proof) challengerExists(challengerId)
    challengerOk(challengerId) travellerExists(travellerId) travellerOk(travellerId) external payable {
        require(msg.value >= proofOfLocationRegistrationFee, "Insufficient fee to register the PoL");

        // checking the traveller confirmed the data
        uint256 traveller_internal_id = toInternalId(travellerId);

        bytes memory traveller_checksum = travellers[traveller_internal_id].checksum;
        bytes32 t_data = keccak256(abi.encodePacked(c_signature));

        verifySigner(t_data, t_signature, traveller_checksum,
            "Traveller signature does not match");

        // checking the challenger confirmed the data
        uint256 challenger_internal_id = toInternalId(challengerId);

        bytes memory challenger_checksum = challengers[challenger_internal_id].checksum;
        bytes32 proof_data = keccak256(abi.encodePacked(c_signature, t_signature));

        verifySigner(proof_data, proof, challenger_checksum,
            "Challenger signature does not match");

        rewardsByChallenger[challenger_internal_id] += proofOfLocationRegistrationFee;
        totalRewards += proofOfLocationRegistrationFee;

        uint256 proofFastId = uint256(keccak256(proof));
        proofs[proofFastId] = ProofOfLocation(
            proofFastId,
            travellerId,
            challengerId,
            nonce_c,
            created_at,
            ttl,
            c_signature,
            t_signature,
            proof,
            true);

        emit ProofOfLocationSubmitted(travellerId, challengerId, proofFastId);
    }

    function equalBytes(bytes memory a, bytes memory b) public pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    function verifySigner(
        bytes32 dataHash,
        bytes memory signature,
        bytes memory expected_address,
        string memory messageOnError
    ) public pure {
        require(signature.length == 65, "Invalid signature length");

        bytes32 ethSignedDataHash = getEthSignedMessageHash(dataHash); // message hash is good

        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature); // this is good.

        address recovered = ecrecover(ethSignedDataHash, v, r, s);

        // This is a quick fix to make it work, should be optimised
        string memory rec_str = removeFirstTwoChars(addrToString(recovered));
        string memory exp_str = removeFirstTwoChars(iToHex(expected_address));

        require(compareStrings(rec_str, exp_str), messageOnError);
    }

    function compareStrings(string memory a, string memory b) public pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function removeFirstTwoChars(string memory str) public pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        require(strBytes.length > 2, "String too short");

        bytes memory result = new bytes(strBytes.length - 2);
        for (uint i = 2; i < strBytes.length; i++) {
            result[i - 2] = strBytes[i];
        }

        return string(result);
    }

    function addrToString(address account) internal pure returns (string memory) {
        return toHexString(uint160(account), 20);
    }

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 + length * 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 + length * 2; i > 1; --i) {
            buffer[i - 1] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        return string(buffer);
    }

    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    function getEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }

    function splitSignature(bytes memory sig)
    internal
    pure
    returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) {
            v += 27;
        }
    }

    function getTravellerPubKey(string memory travellerId) travellerExists(travellerId) travellerOk(travellerId)
    public view returns (bytes memory) {
        uint256 id = toInternalId(travellerId);
        return travellers[id].pubKey;
    }

    function getChallengerPubKey(string memory challengerId) challengerExists(challengerId) challengerOk(challengerId)
    public view returns (bytes memory) {
        uint256 id = toInternalId(challengerId);
        return challengers[id].pubKey;
    }

    function getProofOfLocation(string memory proof)
    external returns (ProofOfLocation memory) {
        return proofs[toInternalId(proof)];
    }

    function blocklistTraveller(string memory travellerId) external onlyOwner {
        uint256 internalId = toInternalId(travellerId);
        travellers[internalId].isBlocklisted = true;
        emit TravellerBlocklisted(travellerId);
    }


    function blocklistChallenger(string memory challengerId) external onlyOwner {
        uint256 internalId = toInternalId(challengerId);
        challengers[internalId].isBlocklisted = true;
        emit ChallengerBlocklisted(challengerId);
    }

    function setChallengerRegistrationFee(uint128 newRegistrationFee) external onlyOwner {
        challengerRegistrationFee = newRegistrationFee;
    }

    function setTravellerRegistrationFee(uint128 newRegistrationFee) external onlyOwner {
        travellerRegistrationFee = newRegistrationFee;
    }


    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function toInternalId(string memory id) public pure returns (uint256) {
        return uint256(keccak256(bytes(id)));
    }

    function iToHex32(bytes32 buffer) public pure returns (string memory) {
        bytes memory converted = new bytes(64);
        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return string(abi.encodePacked("0x", converted));
    }

    function iToHex(bytes memory buffer) public pure returns (string memory) {
        bytes memory converted = new bytes(buffer.length * 2);
        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return string(abi.encodePacked("0x", converted));
    }

    function uint2str(uint256 _i) internal pure returns (string memory str) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        j = _i;
        while (j != 0) {
            bstr[--k] = bytes1(uint8(48 + j % 10));
            j /= 10;
        }
        str = string(bstr);
    }

    function uint8ToString(uint8 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 temp = _i;
        uint256 length;
        while (temp != 0) {
            length++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(length);
        while (_i != 0) {
            length--;
            buffer[length] = bytes1(uint8(48 + (_i % 10)));
            _i /= 10;
        }
        return string(buffer);
    }
}