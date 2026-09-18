const express = require('express');
const cors = require('cors');
const { buildPoseidon } = require('circomlibjs');
const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 1. ISSUE CREDENTIAL: Takes the DOB, generates a salt, and returns a Poseidon hash commitment
app.post('/issue-credential', async (req, res) => {
    try {
        const { dob } = req.body;
        
        const salt = Math.floor(Math.random() * 10000000000); 
        
        const poseidon = await buildPoseidon();
        const hash = poseidon([dob, salt]);
        const commitment = poseidon.F.toString(hash);

        res.json({ commitment, salt });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. VERIFY PROOF: Verifies the client's Groth16 proof without ever seeing the DOB
app.post('/verify-proof', async (req, res) => {
    try {
        const { proof, publicSignals } = req.body;
        
        const vKey = JSON.parse(fs.readFileSync(path.join(__dirname, 'verification_key.json')));

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
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
});