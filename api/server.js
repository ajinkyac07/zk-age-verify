const express = require('express');
const cors = require('cors');
const { buildPoseidon } = require('circomlibjs');
const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Helper function to get today's date as YYYYMMDD integer
function getCurrentDateInt() {
    const d = new Date();
    return parseInt(`${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`);
}

// 1. ISSUANCE ENDPOINT: Simulates a trusted ID issuer
app.post('/issue-credential', async (req, res) => {
    try {
        const { dob } = req.body; // Expecting YYYYMMDD (e.g., 20050101)
        
        // Generate a random salt
        const salt = Math.floor(Math.random() * 10000000000); 
        
        // Compute Poseidon Hash (Commitment)
        const poseidon = await buildPoseidon();
        const hash = poseidon([dob, salt]);
        const commitment = poseidon.F.toString(hash);

        // In a real app, the server saves the commitment, and returns the salt to the user's phone.
        res.json({ commitment, salt });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. PROOF GENERATION ENDPOINT: Simulates the user's app generating a proof
app.post('/generate-proof', async (req, res) => {
    try {
        const { dob, salt, commitment } = req.body;
        const currentDate = getCurrentDateInt();
        const minAgeThreshold = 180000; // 18 years in our date math

        const inputs = {
            dob: dob,
            salt: salt,
            currentDate: currentDate,
            minAgeThreshold: minAgeThreshold,
            commitment: commitment
        };

        // Generate the proof using snarkjs
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            inputs,
            path.join(__dirname, "age_check.wasm"),
            path.join(__dirname, "age_check_final.zkey")
        );

        res.json({ proof, publicSignals });
    } catch (error) {
        res.status(500).json({ error: "Failed to generate proof. Check inputs." });
    }
});

// 3. VERIFICATION ENDPOINT: The actual B2B product (Platform verifying the proof)
app.post('/verify-proof', async (req, res) => {
    try {
        const { proof, publicSignals } = req.body;
        
        // Load the verification key Person A provided
        const vKey = JSON.parse(fs.readFileSync(path.join(__dirname, 'verification_key.json')));

        // Verify the proof
        const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);

        if (isValid) {
            res.json({ verified: true, age_over_18: true, message: "Valid Proof! DOB was kept secret." });
        } else {
            res.status(400).json({ verified: false, message: "Invalid Proof." });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Endpoints ready: /issue-credential, /generate-proof, /verify-proof`);
});