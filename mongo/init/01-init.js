db = db.getSiblingDB('datasetPolicies');

// --- Exact-filename policies ---
db.createCollection('policies');
db.policies.createIndex({ filename: 1 }, { unique: true });

// --- Prefix-based policies ---
db.createCollection('prefix_policies');
db.prefix_policies.createIndex({ prefix: 1 }, { unique: true });

db.prefix_policies.insertMany([
    {
        prefix: "vodafone",
        required_roles: ["developer", "operator"],
        match: "any",
        encryption_attributes: ["itsec", "csirt"]
    },
    {
        prefix: "motorola",
        required_roles: ["itsec", "csirt", "admin"],
        match: "any",
        encryption_attributes: ["itsec", "csirt"]
    },
    {
        prefix: "nokia",
        required_roles: ["itsec", "admin"],
        match: "any",
        encryption_attributes: [ "csirt"]
    }
    

]);

db.policies.insertMany([
    {
        filename: "default",
        required_roles: ["developer", "operator"],
        match: "all",
        encryption_attributes: ["itsec", "csirt", "euisac"]
    },
    {
        filename: "dataset1.pdf",
        required_roles: ["itsec", "csirt", "admin"],
        match: "all",
        encryption_attributes: ["itsec", "csirt", "euisac"]
    },
    {
        filename: "dataset2.pdf",
        required_roles: ["itsec", "admin"],
        match: "any",
        encryption_attributes: ["itsec", "csirt"]
    },
    {
        filename: "dataset3.pdf",
        required_roles: ["csirt", "admin"],
        match: "any",
        encryption_attributes: ["csirt", "euisac"]
    }
]);
