#!/usr/bin/bash
heroku apps:destroy -a $(heroku apps | grep -v -e '^$' | awk 'END {print $1}') --confirm $(heroku apps | grep -v -e '^$' | awk 'END {print $1}')
rm -rf Octopus
heroku create #--buildpack heroku/python
heroku labs:enable runtime-dyno-metadata -a $(heroku apps | grep -v -e '^$' | awk 'END {print $1}')
heroku buildpacks:add --index 1 heroku/python -a $(heroku apps | grep -v -e '^$' | awk 'END {print $1}')
git clone https://github.com/mhaskar/Octopus
cd Octopus
sed -i '24ilistener = NewListener("startup","0.0.0.0",os.environ["PORT"], "0.0.0.0","1","r");listener.start_listener();listener.create_path();listeners=listener' octopus.py
printf  '\n\n@app.after_request\ndef after_request_func(response):\n        response.data=response.data.replace(b"0.0.0.0", bytes(os.environ["HEROKU_APP_NAME"]+".herokuapp.com","utf8")).replace(bytes(":"+os.environ["PORT"],"utf8"),b"")\n        return response' >> core/weblistener.py
echo "web: python3 octopus.py" > Procfile
git add .
git commit -m --allow-empty
heroku git:remote -a $(heroku apps | grep -v -e '^$' | awk 'END {print $1}')
git push heroku HEAD:master
heroku run bash -c "python3 octopus.py" -a $(heroku apps | grep -v -e '^$' | awk 'END {print $1}')
