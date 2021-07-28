import io,sys
PUSH_DATA,STOP,INTERUPT_HISTORY,SEQ_NUM = "",False,False,0
history_buffer = stdout_buffer = io.StringIO()


# def capture_stdout():
#     global stdout_buffer,PUSH_DATA,SEQ_NUM
#     history_buffer.write(stdout_buffer.getvalue())
#     stdout_buffer = io.StringIO()
#     sys.stdout = stdout_buffer

# def release_stdout():
#     global stdout_buffer,PUSH_DATA,SEQ_NUM
#     PUSH_DATA = stdout_buffer.getvalue()
#     sys.stdout = sys.__stdout__
#     SEQ_NUM += 1
#     return PUSH_DATA