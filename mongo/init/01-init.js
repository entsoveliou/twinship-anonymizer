db = db.getSiblingDB('datasetPolicies');

db.createCollection('policies');

// Unique index on filename — "default" is the fallback policy
db.policies.createIndex({ filename: 1 }, { unique: true });

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
