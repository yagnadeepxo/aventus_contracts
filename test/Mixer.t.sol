pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {Tornado} from "../src/Mixer.sol";
import {Hasher} from "../src/MiMCSponge.sol";
import {Verifier} from "../src/Verifier.sol";

contract MixerTest is Test {
    Tornado public mixer;
    Hasher public hasher = new Hasher();
    Verifier public verifier = new Verifier();

    function setUp() external {
        mixer = new Tornado(address(hasher), address(verifier));
    }

    function testDeposit() external {
        mixer.deposit{value: 0.2 ether}(100);
    }
}
