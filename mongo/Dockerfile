FROM mongo:latest

# Root credentials (override via --build-arg or environment at runtime)
ENV MONGO_INITDB_ROOT_USERNAME=root
ENV MONGO_INITDB_ROOT_PASSWORD=rootpassword
ENV MONGO_INITDB_DATABASE=datasetPolicies

# Copy initialisation scripts — these run in alphabetical order on first start
COPY init/ /docker-entrypoint-initdb.d/

EXPOSE 27017
