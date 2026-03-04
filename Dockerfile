# Use an official lightweight Python image
FROM python:3.10-slim

# Set environment variables
# PYTHONUNBUFFERED=1 ensures print statements appear in logs immediately
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# Run the application
# We use python main.py because your main.py has the uvicorn.run block
CMD ["python", "main.py"]