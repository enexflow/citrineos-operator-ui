# SPDX-FileCopyrightText: 2025 Contributors to the CitrineOS Project
#
# SPDX-License-Identifier: Apache-2.0

FROM refinedev/node:22
WORKDIR /app/refine

# Copy .env file if it exists, then export VITE_* variables before build
COPY . .

# Install dependencies first, then use dotenv-cli to load .env and build
# dotenv-cli will automatically use .env file if it exists, or skip if it doesn't
RUN npm i && npx dotenv-cli -- npm run build

RUN npm install -g serve
COPY docker-entrypoint.sh /app/refine/docker-entrypoint.sh
RUN chmod +x /app/refine/docker-entrypoint.sh
WORKDIR /app/refine/dist
CMD ["/app/refine/docker-entrypoint.sh"]
