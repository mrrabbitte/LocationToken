pragma solidity ^0.8.0;

contract LocationToken {

    // both latitude and longitude has to be saved in the same scale
    // to get the real value, you need to divide by the scale, i.e.
    // a) real_lat = lat / scale
    // b) real_lon = lon / scale
    struct Location {
        uint32 scale;
        uint64 lat; // whole number of the real latitude * scale
        uint64 lon; // whole number of the real longitude * scale
    }

    struct Challenger {
        string id;
        address challengerAddress;
        bytes pubKey;
        string wifiNetwork;
        Location location;
        bool isBlocklisted;
    }

    struct Traveller {
        string id;
        address travellerAddress;
        bytes pubKey;
        bool isBlocklisted;
    }

    struct ProofOfLocation {
        string travellerId;
        string challengerId;
        string nonce_c;
        uint64 created_at;
        uint64 ttl;
        string c_signature;
        string t_signature;
        string proof;
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
        string indexed proofOfLocationId
    );
    event ChallengerRegistered(string indexed challengerId, Location location, string wifiNetwork);
    event TravellerBlocklisted(string indexed travellerId);
    event ChallengerBlocklisted(string indexed challengerId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this action");
        _;
    }

    modifier travellerOk(string travellerId) {
        uint256 internalId = toInternalId(travellerId);
        require(!travellers[internalId].isBlocklisted, "You are blocklisted");
        _;
    }

    modifier challengerOk(string challengerId) {
        uint256 memory internalId = toInternalId(challengerId);
        require(!challengers[internalId].isBlocklisted, "You are blocklisted");
        _;
    }

    constructor() {
        owner = msg.sender;
        challengerRegistrationFee = 0.0001 ether;
        travellerRegistrationFee = 0.0001 ether;
        proofOfLocationRegistrationFee = 0.0001 ether;
    }

    function registerChallenger(
        bytes memory challengerPubKey,
        string memory challengerId,
        string memory wifiNetwork,
        uint32 scale,
        uint64 lat,
        uint64 lon) challengerOk(challengerId) external payable {
        require(msg.value >= challengerRegistrationFee, "Insufficient fee to register the challenger");

        uint256 memory internalId = toInternalId(challengerId);

        require(!challengers[internalId], "Challenger is already registered.");

        Location memory location = Location(scale, lat, lon);

        challengers[internalId] = Challenger(
            challengerId,
            msg.sender,
            challengerPubKey,
            wifiNetwork,
            location,
            false);
        rewardsByChallenger[internalId] = 0;

        emit ChallengerRegistered(msg.sender, location, wifiNetwork);
    }


    function registerTraveller(
        string memory travellerId,
        bytes memory travellerPubKey) travellerOk(travellerId) external payable {
        require(msg.value >= challengerRegistrationFee, "Insufficient fee to register the traveller");

        uint256 memory internalId = toInternalId(travellerId);

        require(!travellers[internalId], "Traveller is already registered.");

        travellers[internalId] = Traveller(
            travellerId,
            msg.sender,
            travellerPubKey,
            false);
    }

    function registerLocationProof(
        string memory travellerId,
        string memory challengerId,
        string memory nonce_c,
        uint64 memory created_at,
        uint64 memory ttl,
        bytes memory c_signature,
        bytes memory t_signature,
        bytes memory proof) challengerOk(challengerId) travellerOk(travellerId) external payable {
        require(msg.value >= proofOfLocationRegistrationFee, "Insufficient fee to register the PoL");

        // checking the challenger has confirmed the data
        uint256 memory challenger_internal_id = toInternalId(challengerId);
        bytes memory challenger_pub_key = challengers[challenger_internal_id].pubKey;
        bytes memory proof_data = keccak256(abi.encodePacked(c_signature, t_signature));

        require(verifySignature(proof_data, proof, challenger_pub_key),
            "Challenger signature does not match.");

        // checking the traveller also confirmed the data
        bytes memory traveller_pub_key = travellers[toInternalId(travellerId)].pubKey;
        bytes memory t_data = keccak256(abi.encodePacked(c_signature));

        require(verifySignature(t_data, t_signature, traveller_pub_key),
            "Traveller signature does not match.");

        rewardsByChallenger[challenger_internal_id] += proofOfLocationRegistrationFee;
        totalRewards += proofOfLocationRegistrationFee;

        proofs[toInternalId(proof)] = ProofOfLocation(
            travellerId,
            challengerId,
            nonce_c,
            created_at,
            ttl,
            c_signature,
            t_signature,
            proof);

        emit ProofOfLocationSubmitted(travellerId, challengerId, proof);
    }

    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory publicKey
    ) public pure returns (bool) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        address recoveredAddress = ecrecover(messageHash, v, r, s);
        address publicKeyAddress = address(uint160(uint256(keccak256(publicKey))));

        return recoveredAddress == publicKeyAddress;
    }

    function getTravellerPubKey(string memory travellerId) external view returns (string memory) {
        return travellers[toInternalId(travellerId)].pubKey;
    }

    function getProofOfLocation(string memory proof)
    external view returns (ProofOfLocation memory) {
        return proof[toInternalId(proof)];
    }

    function blocklistTraveller(string memory travellerId) external onlyOwner {
        uint256 internalId = internalId(travellerId);
        travellers[internalId].isBlocklisted = true;
        emit TravellerBlocklisted(travellerId);
    }


    function blocklistChallenger(string memory challengerId) external onlyOwner {
        uint256 internalId = internalId(challengerId);
        challengers[internalId].isBlocklisted = true;
        emit ChallengerBlocklisted(challengerId);
    }

    function setChallengerRegistrationFee(uint256 newRegistrationFee) external onlyOwner {
        challengerRegistrationFee = newRegistrationFee;
    }

    function setTravellerRegistrationFee(uint256 newRegistrationFee) external onlyOwner {
        travellerRegistrationFee = newRegistrationFee;
    }


    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function toInternalId(string memory id) returns (uint256) {
        return uint256(keccak256(bytes(id)));
    }
}