pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template AgeCheck() {
    // Private inputs (User's device)
    signal input dob; // e.g., 20050101 (YYYYMMDD)
    signal input salt;
    
    // Public inputs (Provided by the platform verifying the age)
    signal input currentDate; // e.g., 20260918 (YYYYMMDD)
    signal input minAgeThreshold; // e.g., 180000 (18 years in YYYYMMDD math)
    signal input commitment; // The Poseidon hash of (dob, salt)

    // Output
    signal output isVerified;

    // 1. Verify the commitment matches the DOB and Salt
    component hasher = Poseidon(2);
    hasher.inputs[0] <== dob;
    hasher.inputs[1] <== salt;
    hasher.out === commitment;

    // 2. Check if (currentDate - dob) >= minAgeThreshold
    component greaterEq = GreaterEqThan(32); // 32-bit comparison
    greaterEq.in[0] <== currentDate - dob;
    greaterEq.in[1] <== minAgeThreshold;
    
    greaterEq.out === 1; // Assert that the user is old enough

    isVerified <== 1;
}

// Instantiate the component
component main {public [currentDate, minAgeThreshold, commitment]} = AgeCheck();