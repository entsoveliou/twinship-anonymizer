# Pinned to 4.4: MongoDB 5.0+ requires AVX CPU support, which this host lacks
# (mongod crashes with "Illegal instruction" on 5.0+ otherwise).
FROM mongo:4.4

# Root credentials (override via --build-arg or environment at runtime)
ENV MONGO_INITDB_ROOT_USERNAME=root
ENV MONGO_INITDB_ROOT_PASSWORD=rootpassword
ENV MONGO_INITDB_DATABASE=datasetPolicies

# Copy initialisation scripts — these run in alphabetical order on first start
COPY init/ /docker-entrypoint-initdb.d/

EXPOSE 27017
