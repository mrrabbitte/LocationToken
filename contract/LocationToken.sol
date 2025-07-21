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
        string pubKey;
        string wifiNetwork;
        Location location;
        bool isBlocklisted;
    }

    struct Traveller {
        string id;
        address travellerAddress;
        string pubKey;
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
    mapping(uint256 => LocationProof) public locationProofs;
    mapping(string => Challenger) public wifiNameToChallenger;

    // Events
    event ProofOfLocationSubmitted(
        uint256 travellerId,
        uint256 challengerId,
        uint256 locationProofId
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
        string memory challengerPubKey,
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

        emit ChallengerRegistered(msg.sender, location, wifiNetwork);
    }


    function registerTraveller(
        string memory travellerId,
        string memory travellerPubKey) travellerOk(travellerId) external payable {
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
        string memory c_signature,
        string memory t_signature,
        string memory proof) challengerOk(challengerId) travellerOk(travellerId) external payable {
        // Remember to change to using to sha256
        ProofOfLocation memory pol =
                        ProofOfLocation(
                travellerId,
                challengerId,
                nonce_c,
                created_at,
                ttl,
                c_signature,
                t_signature,
                proof);
    }

    function getTravellerPubKey(string memory travellerId) external view returns (string memory) {
        return travellers[toInternalId(travellerId)].pubKey;
    }

    function getLocationProof(string memory proof)
    external view returns (ProofOfLocation memory) {
        return locationProofs[toInternalId(proof)];
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