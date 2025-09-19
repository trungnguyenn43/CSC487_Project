# CSC487_Project

# Docker setup
Please run these lines below to set up docker for testing purpose:

1. Build and start the containers using the following command:
   ```bash
   docker-compose up --build
   ```

2. To stop the containers, use:
   ```bash
   docker-compose down
   ```

3. To access the first container (Machine_1), run:
   ```bash
   docker exec -it Machine_1 bash
   ```

4. To access the second container (Machine_2), run:
   ```bash
   docker exec -it Machine_2 bash
   ```
