const term = new Terminal({cursorBlink:true, theme: {background: 'black'}})
        term.loadAddon(new FitAddon.FitAddon())
        term.open(document.getElementById('terminal'))


        

        //term.textarea

        const width = window.innerWidth
        const height = window.innerHeight 
        cols = parseInt(width / 9, 10)
        term.resize(cols, parseInt(height / 17, 10))
        term.scrollToBottom()
        
        var prev_line = ""
        var session_id = -1
        var term_str = "\r\n\x1b[4mOctopus\x1b[0m\x1b[32m >>\x1b[0m "

        var command_buff = Array()
        var commands_buff = Array()
        var commands_buff_index = 0

        var term_core_buffer = 11


        var aliasses = {
            "h":"history",
            "b":"banner",
            "l":"list",
        }

        function command_muzzle(command){
            var command = aliasses[command] ? aliasses[command] : command
            if(command == "clear"){
                term.write('\033[2J')
                term.prompt()
                return ""
            }
            return command
        }
        
        function runFakeTerminal() {
            if (term._initialized) {
                return
            }
            term._initialized = true
            term.prompt = () => {
                term.write(term_str)
            }
            
            term.prompt()

            term.onData(e => {
                switch (e) {
                    case '\r':
                        var command = command_muzzle(command_buff.join(""))
                        commands_buff.unshift(command)
                        loadAndWrite(command)
                        command_buff.length = 0
                        commands_buff_index = 0
                        break
                    case '\u001b[A':
                        if(commands_buff_index < commands_buff.length){
                            var up_command = commands_buff[commands_buff_index++]
                            clear_terminal_line()
                            term.write(up_command)
                        }
                        break
                    case '\u001b[B':
                        if(commands_buff_index > 0){
                            var down_command = commands_buff[--commands_buff_index]
                        }
                        else{
                            var down_command = command_buff.join("")
                        }
                            
                        clear_terminal_line()
                        term.write(down_command)
                        break
                    case '\u0003':
                        break
                    case '\u007F':
                        remove_char()
                        command_buff.pop()
                        break
                    default:
                        term.write(e)
                        command_buff.push(e)
                }
            })
        }

        function remove_char(){
            if(term._core.buffer.x > term_core_buffer){
                term.write('\b \b')
            }
        }

        function clear_terminal_line(){
            term.write('\x1b[2K')    
            term.write(term_str.replace("\n",""))
        }


        setTimeout(function() {
            send_command_request("history")
        }, 900);

        prev_seq_num = "-1"
        const sse = new EventSource('/sse')
        sse.onmessage = (msg) => {
                var data = msg.data
                var div = document.getElementById('terminal')
                var [data,seq_num] = data.split("<SEQ_NUM>")
                var data = decodeURIComponent(data)
                data = data.replace(/\<NEWLINE\>/g, '\n\r')
                if(data.trim().length && 
                    seq_num != prev_seq_num){
                    term.write(data)
                    prev_seq_num = seq_num
                    term.prompt()   
                }
        }
        
        window.onbeforeunload = function() {
            sse.close()
        }
        
        function send_command_request(command){
            var formData = new FormData()
            formData.append("input", command)
            formData.append("session_id", session_id)
            fetch(window.location.href, {
                method: "POST",
                body: formData,
            }).then((response) => {
                response.text()
                    .then( raw => raw.replace(/\n/g, '\n\r') )
            })
        }

        function loadAndWrite(command) {
            if(command.startsWith("interact") && session_id === -1){
                session_id = command.split(" ")[1]
                term_str = "\r\n([31m" + session_id + "[0m) >> "
                term_core_buffer = (6 + session_id.length)
                return
            }
            if(session_id > -1 && command == "exit"){
                session_id = -1
                term_str = "\r\n\x1b[4mOctopus\x1b[0m\x1b[32m >>\x1b[0m "
                term_core_buffer = 11
                term.prompt()
                return
            }
            send_command_request(command)
            term.prompt()
        }
        runFakeTerminal()