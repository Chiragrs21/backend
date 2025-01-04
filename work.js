const fs = require('fs');

// Load the sample.json file
const rawData = fs.readFileSync('scan_results.json');
const data = JSON.parse(rawData);

// Extract account details
const accountDetails = data.data.account_details;

// Filter for platforms where registered is true
const registeredPlatforms = Object.entries(accountDetails)
    .filter(([platform, details]) => details.registered === true)
    .map(([platform, details]) => platform);

// Output the list of registered platforms
console.log("List of Social Media Platforms where 'registered' is true:");
console.log(registeredPlatforms);