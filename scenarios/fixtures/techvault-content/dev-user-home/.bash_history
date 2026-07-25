ls -la
cd projects/techvault-portal
git pull origin main
cat .env
ssh labadmin@172.20.2.20
sshpass -p 'LabAdmin2024!' ssh labadmin@172.20.2.20
psql -h 172.20.2.11 -U techvault -d techvault -W
curl -X POST http://172.20.2.25:8080/login -d "username=admin&password=admin123"
ssh contractor.temp@172.20.2.10 -p Welcome1!
cat ~/.pgpass
docker logs aptl-webapp --tail 50
