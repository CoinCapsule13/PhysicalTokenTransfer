// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Address.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Votes} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract IconoclastSwarmToken is ERC20, ERC20Permit, ERC20Votes, Ownable {
    constructor(address recipient, address initialOwner)
        ERC20("Iconoclast Swarm Token", "IST")
        ERC20Permit("Iconoclast Swarm Token")
        Ownable(initialOwner)
    {
        _mint(recipient, 1000000000 * 10 ** decimals());
    }

    function clock() public view override returns (uint48) {
        return uint48(block.timestamp);
    }

    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() public pure override returns (string memory) {
        return "mode=timestamp";
    }

    // The following functions are overrides required by Solidity.

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Votes)
    {
        super._update(from, to, value);
    }

    function nonces(address owner)
        public
        view
        override(ERC20Permit, Nonces)
        returns (uint256)
    {
        return super.nonces(owner);
    }
}

/**
 * @title PhysicalTokenTransfer
 * @notice A secure voucher system for ETH and ERC20 tokens using password-based redemption.
 *
 * The voucher “code” is composed of:
 *  - A unique voucher ID (generated on deposit)
 *  - A secret password chosen by the depositor.
 *
 * The contract stores only a hash computed as:
 *     secretHash = keccak256(abi.encodePacked(voucherId, password))
 *
 * To transfer a voucher, its current owner (i.e. the current holder of the secret)
 * must supply the voucher ID and its current password; then they can set a new password.
 *
 * To redeem a voucher, the redeemer must supply the voucher ID along with the correct password.
 */

contract PhysicalTokenTransfer is ReentrancyGuard, Pausable, Ownable {
    using SafeERC20 for IERC20;
    using Address for address payable;

    uint256 public constant FEE_NUMERATOR = 1;
    uint256 public constant FEE_DENOMINATOR = 1000;

    /// @notice Address that collects fees.
    address public feeCollector;

    /// @dev Counter used to generate unique voucher IDs.
    uint256 private _voucherCounter = 1;

    struct Voucher {
        uint256 amount;
        bytes32 secretHash; // Only the hashed password is stored.
        uint256 transferCount;
        bool redeemed;
        bool isEth;
        address tokenAddress;
        uint256 createdAt;
        uint256 lastTransferAt;
        address depositor; // Original voucher creator.
        address redeemer;  // Address that redeems the voucher.
    }

    /// @notice Mapping from voucher ID to voucher data.
    mapping(uint256 => Voucher) public vouchers;

    // -------------------- Events --------------------

    event VoucherCreated(
        uint256 indexed voucherId,
        uint256 netAmount,
        bool isEth,
        address tokenAddress,
        uint256 createdAt,
        address depositor
    );
    event VoucherTransferred(
        uint256 indexed voucherId,
        uint256 transferCount,
        uint256 lastTransferAt
    );
    event VoucherRedeemed(
        uint256 indexed voucherId,
        uint256 netAmount,
        bool isEth,
        address tokenAddress,
        address recipient,
        uint256 redeemedAt,
        address depositor
    );
    event FeeCollectorUpdated(address indexed newFeeCollector);
    event ContractPaused(address account);
    event ContractUnpaused(address account);

    // -------------------- Constructor --------------------

    /**
     * @notice Initializes the contract with a fee collector.
     * @param _feeCollector The address that will receive fees.
     */
    constructor(address _feeCollector) Ownable(msg.sender) {
        require(_feeCollector != address(0), "Invalid fee collector address");
        feeCollector = _feeCollector;
    }

    // -------------------- Administration --------------------

    /**
     * @notice Update the fee collector address.
     * @param _newFeeCollector The new fee collector address.
     */
    function setFeeCollector(address _newFeeCollector) external onlyOwner {
        require(_newFeeCollector != address(0), "Invalid fee collector address");
        feeCollector = _newFeeCollector;
        emit FeeCollectorUpdated(_newFeeCollector);
    }

    /**
     * @notice Pause the contract.
     */
    function pause() external onlyOwner {
        _pause();
        emit ContractPaused(msg.sender);
    }

    /**
     * @notice Unpause the contract.
     */
    function unpause() external onlyOwner {
        _unpause();
        emit ContractUnpaused(msg.sender);
    }

    // -------------------- Voucher Functions --------------------

    /**
     * @notice Deposit ERC20 tokens to create a voucher.
     * @param token Address of the ERC20 token.
     * @param amount Amount to deposit.
     * @param passwordHash The pre-computed hash (bytes32) of the chosen password.
     *
     * Emits a {VoucherCreated} event.
     */
    function depositERC20(
        address token,
        uint256 amount,
        bytes32 passwordHash
    ) external nonReentrant whenNotPaused {
        require(token != address(0) && amount > 0, "Invalid token or amount");
        require(passwordHash != bytes32(0), "Password hash cannot be zero");

        // Calculate fee and net deposit amount.
        uint256 fee = (amount * FEE_NUMERATOR) / FEE_DENOMINATOR;
        uint256 netAmount = amount - fee;

        // Transfer tokens from the sender.
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        // Transfer fee to feeCollector.
        IERC20(token).safeTransfer(feeCollector, fee);

        // Generate voucher ID.
        uint256 voucherId = _voucherCounter++;

        // Create the voucher.
        vouchers[voucherId] = Voucher({
            amount: netAmount,
            secretHash: passwordHash,
            transferCount: 0,
            redeemed: false,
            isEth: false,
            tokenAddress: token,
            createdAt: block.timestamp,
            lastTransferAt: block.timestamp,
            depositor: msg.sender,
            redeemer: address(0)
        });

        emit VoucherCreated(voucherId, netAmount, false, token, block.timestamp, msg.sender);
    }

    /**
     * @notice Deposit ETH to create a voucher.
     * @param passwordHash The pre-computed hash (bytes32) of the chosen password.
     *
     * Emits a {VoucherCreated} event.
     */
    function depositETH(bytes32 passwordHash) external payable nonReentrant whenNotPaused {
        require(msg.value > 0, "Deposit amount must be > 0");
        require(passwordHash != bytes32(0), "Password hash cannot be zero");

        uint256 fee = (msg.value * FEE_NUMERATOR) / FEE_DENOMINATOR;
        uint256 netAmount = msg.value - fee;

        // Transfer fee to feeCollector.
        payable(feeCollector).transfer(fee);

        // Generate voucher ID.
        uint256 voucherId = _voucherCounter++;

        // Create the voucher.
        vouchers[voucherId] = Voucher({
            amount: netAmount,
            secretHash: passwordHash,
            transferCount: 0,
            redeemed: false,
            isEth: true,
            tokenAddress: address(0),
            createdAt: block.timestamp,
            lastTransferAt: block.timestamp,
            depositor: msg.sender,
            redeemer: address(0)
        });

        emit VoucherCreated(voucherId, netAmount, true, address(0), block.timestamp, msg.sender);
    }

    /**
     * @notice Transfer a voucher by updating its password.
     * @param voucherId The ID of the voucher to transfer.
     * @param oldPassword The current plaintext password to verify.
     * @param newPasswordHash The new pre-computed password hash (bytes32).
     *
     * Allows an anonymous transfer by updating the stored password hash.
     * Emits a {VoucherTransferred} event.
     */
    function transferVoucher(
        uint256 voucherId,
        string calldata oldPassword,
        bytes32 newPasswordHash
    ) external nonReentrant whenNotPaused {
        require(bytes(oldPassword).length > 0, "Old password cannot be empty");
        require(newPasswordHash != bytes32(0), "New password hash cannot be zero");

        Voucher storage voucher = vouchers[voucherId];
        require(!voucher.redeemed, "Voucher already redeemed");

        // Verify that the provided old password is correct.
        require(
            keccak256(abi.encodePacked(oldPassword)) == voucher.secretHash,
            "Incorrect current password"
        );
        // Ensure the new password hash is different.
        require(newPasswordHash != voucher.secretHash, "New password must be different");

        // Update the secret hash to the new password hash.
        voucher.secretHash = newPasswordHash;
        voucher.transferCount++;
        voucher.lastTransferAt = block.timestamp;

        emit VoucherTransferred(voucherId, voucher.transferCount, block.timestamp);
    }

    /**
     * @notice Redeem a voucher to claim the deposited funds.
     * @param voucherId The ID of the voucher to redeem.
     * @param password The plaintext password to verify.
     * @param recipient The address to which the assets will be redeemed.
     *
     * If the provided password is correct, the voucher is marked as redeemed and
     * funds are transferred to the specified recipient.
     * Emits a {VoucherRedeemed} event.
     */
    function redeemVoucher(
        uint256 voucherId,
        string calldata password,
        address recipient
    ) external nonReentrant whenNotPaused {
        require(recipient != address(0), "Invalid recipient address");
        require(bytes(password).length > 0, "Password cannot be empty");

        Voucher storage voucher = vouchers[voucherId];
        require(!voucher.redeemed, "Voucher already redeemed");

        // Verify the password.
        require(
            keccak256(abi.encodePacked(password)) == voucher.secretHash,
            "Incorrect password"
        );

        // Mark voucher as redeemed and record the redeemer.
        voucher.redeemed = true;
        voucher.redeemer = recipient;

        uint256 amount = voucher.amount;
        if (voucher.isEth) {
            payable(recipient).transfer(amount);
        } else {
            IERC20(voucher.tokenAddress).safeTransfer(recipient, amount);
        }

        emit VoucherRedeemed(voucherId, amount, voucher.isEth, voucher.tokenAddress, recipient, block.timestamp, voucher.depositor);
    }

    // -------------------- Fallback Functions --------------------

    /// @notice Allows the contract to receive ETH.
    receive() external payable {}

    /// @notice Fallback function.
    fallback() external payable {}
}


contract MultiAssetVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // -------------------- Withdrawal Variables --------------------
    mapping(address => bool) public isValidWithdrawalAddress;

    // -------------------- Staking State Variables --------------------
    /// @notice The token that users will stake to earn fee rewards.
    IERC20 public stakingToken;

    /// @notice Total tokens staked.
    uint256 public totalStaked;

    /// @notice Mapping of user staked balances.
    mapping(address => uint256) public stakedBalances;

    /**
     * @notice Accumulated rewards per staked token (scaled by 1e18).
     * When new rewards are deposited, this value increases.
     */
    uint256 public accRewardPerShare;

    /**
     * @notice Mapping of each user's reward debt.
     * This is used to calculate pending rewards.
     */
    mapping(address => uint256) public userRewardDebt;

    /**
     * @notice Mapping of pending (accumulated but unclaimed) rewards for each user.
     */
    mapping(address => uint256) public pendingRewards;

    // -------------------- Events --------------------
    event ERC20FeesCollected(address indexed token, address indexed from, uint256 amount);
    event ERC20Withdrawal(address indexed token, address indexed to, uint256 amount);
    event ETHFeesCollected(address indexed from, uint256 amount);
    event ETHWithdrawal(address indexed to, uint256 amount);
    event ValidAddressUpdated(address indexed validAddress, bool isValid);

    // Staking events
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 reward);
    event RewardsDeposited(uint256 amount);
    event StakingTokenUpdated(address stakingToken);

    // -------------------- Constructor --------------------
    constructor() Ownable(msg.sender) {}

    // -------------------- Fee Collection Functions --------------------

    /**
     * @notice Accept ETH fees.
     */
    receive() external payable {
        emit ETHFeesCollected(msg.sender, msg.value);
    }

    /**
     * @notice Collect ERC20 fees by transferring tokens into the vault.
     * @param token The ERC20 token.
     * @param amount The amount to collect.
     */
    function collectERC20Fees(IERC20 token, uint256 amount) external nonReentrant {
        require(amount > 0, "Amount must be > 0");
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit ERC20FeesCollected(address(token), msg.sender, amount);
    }

    // -------------------- Withdrawal Functions --------------------

    /**
     * @notice Withdraw ETH from the vault.
     * @param to The recipient address (must be whitelisted).
     * @param amount The amount to withdraw.
     */
    function withdrawETH(address payable to, uint256 amount) external onlyOwner nonReentrant {
        require(isValidWithdrawalAddress[to], "Invalid withdrawal address");
        require(address(this).balance >= amount, "Insufficient ETH balance");

        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");

        emit ETHWithdrawal(to, amount);
    }

    /**
     * @notice Withdraw ERC20 tokens from the vault.
     * @param token The ERC20 token.
     * @param to The recipient address (must be whitelisted).
     * @param amount The amount to withdraw.
     */
    function withdrawERC20(IERC20 token, address to, uint256 amount) external onlyOwner nonReentrant {
        require(isValidWithdrawalAddress[to], "Invalid withdrawal address");
        require(token.balanceOf(address(this)) >= amount, "Insufficient ERC20 balance");

        token.safeTransfer(to, amount);
        emit ERC20Withdrawal(address(token), to, amount);
    }

    /**
     * @notice Update (whitelist/unwhitelist) a withdrawal address.
     * @param _address The address to update.
     * @param _isValid True if the address should be allowed to receive withdrawals.
     */
    function updateValidWithdrawalAddress(address _address, bool _isValid) external onlyOwner {
        isValidWithdrawalAddress[_address] = _isValid;
        emit ValidAddressUpdated(_address, _isValid);
    }

    // -------------------- Staking Functions --------------------

    /**
     * @notice Set or update the staking token.
     * @param _stakingToken The address of the token to be used for staking.
     *
     * This token will also be used for distributing fee rewards.
     */
    function setStakingToken(address _stakingToken) external onlyOwner {
        require(_stakingToken != address(0), "Invalid staking token address");
        stakingToken = IERC20(_stakingToken);
        emit StakingTokenUpdated(_stakingToken);
    }

    /**
     * @notice Stake tokens to earn a share of fee rewards.
     * @param amount The amount of staking tokens to stake.
     */
    function stake(uint256 amount) external nonReentrant {
        require(address(stakingToken) != address(0), "Staking token not set");
        require(amount > 0, "Cannot stake 0");

        // Update the user's rewards before modifying their stake.
        _updateReward(msg.sender);

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
        stakedBalances[msg.sender] += amount;
        totalStaked += amount;

        // Update the user's reward debt.
        userRewardDebt[msg.sender] = (stakedBalances[msg.sender] * accRewardPerShare) / 1e18;

        emit Staked(msg.sender, amount);
    }

    /**
     * @notice Withdraw staked tokens.
     * @param amount The amount of staking tokens to withdraw.
     */
    function withdrawStake(uint256 amount) external nonReentrant {
        require(amount > 0, "Cannot withdraw 0");
        require(stakedBalances[msg.sender] >= amount, "Insufficient staked balance");

        // Update the user's rewards before modifying their stake.
        _updateReward(msg.sender);

        stakedBalances[msg.sender] -= amount;
        totalStaked -= amount;
        stakingToken.safeTransfer(msg.sender, amount);

        // Update the user's reward debt.
        userRewardDebt[msg.sender] = (stakedBalances[msg.sender] * accRewardPerShare) / 1e18;

        emit Withdrawn(msg.sender, amount);
    }

    /**
     * @notice Claim accumulated reward tokens.
     */
    function claimRewards() external nonReentrant {
        _updateReward(msg.sender);

        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "No rewards to claim");

        pendingRewards[msg.sender] = 0;
        stakingToken.safeTransfer(msg.sender, reward);
        emit RewardClaimed(msg.sender, reward);
    }

    /**
     * @notice Deposit reward tokens (fees) to be distributed among stakers.
     * @param amount The amount of reward tokens to deposit.
     *
     * This function should be called when fee tokens (of the same type as the staking token)
     * are available for distribution.
     */
    function depositRewards(uint256 amount) external onlyOwner nonReentrant {
        require(address(stakingToken) != address(0), "Staking token not set");
        require(amount > 0, "Amount must be > 0");

        // Transfer the reward tokens into the vault.
        stakingToken.safeTransferFrom(msg.sender, address(this), amount);

        // Update the accumulated reward per share if there are staked tokens.
        if (totalStaked > 0) {
            accRewardPerShare += (amount * 1e18) / totalStaked;
        }
        emit RewardsDeposited(amount);
    }

    /**
     * @dev Internal function to update a staker's pending rewards.
     * @param account The staker's address.
     */
    function _updateReward(address account) internal {
        if (totalStaked > 0) {
            uint256 accrued = (stakedBalances[account] * accRewardPerShare) / 1e18;
            if (accrued > userRewardDebt[account]) {
                pendingRewards[account] += accrued - userRewardDebt[account];
            }
        }
        userRewardDebt[account] = (stakedBalances[account] * accRewardPerShare) / 1e18;
    }
}




contract TokenSale {
    address public owner;
    IERC20 public token;  // ERC20 token address
    address payable public vault;  // Vault contract address for receiving ETH
    uint256 public pricePerTokenInEth; // Price per token in ETH

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier validAmount() {
        require(msg.value > 0, "Must send ETH to purchase tokens");
        _;
    }

    // Constructor to initialize contract with ERC20 token and vault addresses
    constructor(address _token, address payable _vault) {
        owner = msg.sender;
        token = IERC20(_token);
        vault = _vault;
        pricePerTokenInEth = 0.000003 ether;  // Fixed price per token
    }

    // Function to buy tokens
    function buyTokens(uint256 _numTokens) external payable validAmount {
        uint256 costInEth = _numTokens * pricePerTokenInEth;
        require(msg.value >= costInEth, "Insufficient ETH sent");

        uint256 tokenBalance = token.balanceOf(address(this));
        require(tokenBalance >= _numTokens, "Not enough tokens available");

        // Send tokens to buyer
        require(token.transfer(msg.sender, _numTokens), "Token transfer failed");

        // Send ETH to Vault contract
        (bool success, ) = vault.call{value: msg.value}("");
        require(success, "Failed to transfer ETH to vault");

        // Refund any excess ETH sent by user
        if (msg.value > costInEth) {
            payable(msg.sender).transfer(msg.value - costInEth);
        }
    }

    // Function to withdraw tokens from the sale contract (only for owner)
    function withdrawTokens(uint256 amount) external onlyOwner {
        uint256 tokenBalance = token.balanceOf(address(this));
        require(tokenBalance >= amount, "Insufficient tokens in contract");
        require(token.transfer(owner, amount), "Token transfer failed");
    }

    // Function to withdraw ETH from the sale contract (only for owner)
    function withdrawEth(uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient ETH balance");
        payable(owner).transfer(amount);
    }

    // Function to update the price of tokens (only for owner)
    function updateTokenPrice(uint256 _newPrice) external onlyOwner {
        pricePerTokenInEth = _newPrice;
    }

    // Function to check contract's balance of ETH
    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // Function to check available tokens for sale
    function availableTokens() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
contract StringHasher {
    /// @notice Returns the keccak256 hash of the input string.
    /// @param input The string to hash.
    /// @return hash The computed keccak256 hash.
    function hashString(string calldata input) external pure returns (bytes32 hash) {
        hash = keccak256(abi.encodePacked(input));
    }
}