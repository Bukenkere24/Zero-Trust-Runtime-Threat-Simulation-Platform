FROM node:20-alpine AS build

WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .

ARG VITE_ATTACKER_URL=http://localhost:5002
ARG VITE_DEFENSE_URL=http://localhost:5001
ENV VITE_ATTACKER_URL=$VITE_ATTACKER_URL
ENV VITE_DEFENSE_URL=$VITE_DEFENSE_URL

RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 5173
CMD ["nginx", "-g", "daemon off;"]
