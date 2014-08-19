

class HypotheticalStateMachine(object):
    """
    Be the state change you want to see in the world.

    A brief note on the semantics here; it should define 3 decorators; 'input',
    'state', and 'output'.

    You provide inputs to the state machine by calling methods decorated with
    'input'.  These methods always return None to the caller, as outputs are
    modeled as side-effects (maybe?).  The body of the method will be executed,
    passing along arguments normally, but then the output method will be
    invoked.

    The state machine emits outputs by calling the methods decorated with
    'output'.  It will pass along any parameters provided to the input with the
    same names as output parameters.

    The 'state'-decorated methods should not have bodies, as they're mostly
    just a place to hang a docstring.  (Possibly we could do something
    contextmanager-y and give them enter/exit behavior but we have no use for
    that yet).

    Finally, the 'transitions' method takes 3 args, 'initial states',
    'transitions', and 'final states'.  Calling this should verify that stuff
    is basically correct, particularly that parameters to input methods and
    output methods match up in all cases.

    Lifecycle management and how _exactly_ the composition of TLSCommon with
    TLSServer and TLSClient works is left as an exercise for the reader.  But
    there should be some composition happening, perhaps 'submachine' needs to
    take an attribute name for a reference to the TLSCommon instance or
    something a-la proxyForInterface.  Or maybe the right way to do this is to
    have separate "client" and "server" negotiation state machines, whose
    terminal state is app_data, and then an app_data / close_alert state
    machine whose initial state is app_data.  That would be a lot cleaner, but
    what throws a rwrench into it is the distinct handling of HelloRequest and
    ClientHello in the app_data state; we might want to address this by having
    the client/server negotiation state machines get that input rather than
    sending it to the app_data/shutdown connection machine.
    """



class TLSCommon(object):
    """
    We should be able to compose this in somewhow.  It's not super important
    that have lots of automatic machinery, a little bit of explicit composition
    would be perfectly clear, but I don't want to copy and paste all of these
    declarations right now so let's pretend we have a workable composition
    idiom for going back and forth between the states common to client and
    server and the states unique to each.  (Woo subclassing, hooray.)
    """

    machine = HypotheticalStateMachine()

    @machine.state
    def app_data(self):
        """
        
        """


    @machine.state
    def shutdown(self):
        """
        The TLS connection is shut down all the way.
        """


    @machine.state
    def host_initiated_closing(self):
        """
        The TLS connection is shut down all the way.
        """


    # The 'output' signature here is a (non-strict) subset of the signature of
    # *all* 'input' methods which lead to it in the transition table.  so since
    # write_app_data has a 'plaintext' argument, the 'write_data' input must
    # have an argument named exactly 'plaintext' as well.

    # However, inputs may happily take parameters which outputs ignore. (?)

    @machine.output
    def write_app_data(self, plaintext):
        """
        
        """
        out = self.outbound_plaintext
        app_data_record = self.encrypt_and_authenticate_and_such(out)
        self.write_callback(app_data_record)


    @machine.input
    def write_data(self, plaintext):
        """
        An input: write some data to the network.

        Note that this should probably be delegated-to by Session.write_data;
        we may want to do some of the guarding / checking in Session first.
        """

    @machine.input
    def received_close_notify(self):
        """
        
        """


    @machine.input
    def close_notify_called(self):
        """
        
        """


    @machine.output
    def send_close_notify(self):
        """
        
        """



    @machine.output
    def close_transport_now(self):
        """
        This should invoke ``close_callback(True)`` where ``close_callback`` is
        from ``.start`` on ``ClientTLS`` or ``ServerTLS``
        """


    @machine.output
    def close_transport_later(self):
        """
        This should invoke ``close_callback(False)`` where ``close_callback``
        is from ``.start`` on ``ClientTLS`` or ``ServerTLS``
        """


    @machine.output
    def indicate_eof(self):
        """
        We don't have a good way to indicate this to the application yet, this
        may need to be another callback to ``start``, but the purpose of this
        output is to indicate that we have an authenticated, encrypted EOF,
        rather than a transport drop.

        Since a transport drop is a lower-level concern, we do not have any API
        within ``tls`` itself for transport drops.
        """


    machine.transitions(
        [], # initial states. none because this isn't a valid machine on its
            # own! it has to be composed with a TLSClient or TLSServer.

            # Transitions: (in-state, input, out-state, outputs).
        [
            (app_data, write_data, app_data, [write_app_data]),
            (app_data, received_close_notify, shutdown,
             [send_close_notify,
              close_transport_later,
              indicate_eof]),
            (app_data, close_notify_called, host_initiated_closing,
             [send_close_notify]),
            (host_initiated_closing, received_close_notify, shutdown,
             [close_transport_now,
              indicate_eof]),
        ],
        [
            shutdown
        ], # Terminal states.
    )



class TLSClient(object):
    """
    
    """

    machine = TLSCommon.submachine()

    @machine.state
    def idle(self):
        """
        
        """


    @machine.state
    def wait_1(self):
        """
        
        """


    @machine.state
    def wait_2(self):
        """
        
        """


    @machine.input
    def receive_finished(self, data):
        """
        A 'finished' message was received from the server.
        """
        self.finished_data_from_server = data


    @machine.input
    def begin(self):
        """
        
        """


    @machine.input
    def receive_server_hello_done(self, server_hello_done):
        """
        The ServerHelloDone message was received.
        """
        


    @machine.output
    def send_client_hello(self):
        """
        Send a client hello.
        """


    @machine.output
    def send_finished(self):
        """
        Send all of the data that the server requires to send its Finished to
        us; send (Maybe) Certificate, a ClientKeyExchange, (Maybe) a
        CertificateVerify, ChangeCipherSpec, and Finished.
        """


    @machine.input
    def buffer(self):
        """
        
        """
        

    machine.transitions(
        [idle],
        [
            (idle, begin, wait_1, [send_client_hello]),
            (wait_1, receive_server_hello_done, wait_2, [send_finished]),
            (wait_2, receive_finished, TLSCommon.app_data, []),
        ],
        [TLSCommon.shutdown]
    )


class TLSServer(object):
    """
    
    """

    machine = TLSCommon.submachine()

    @machine.state
    def idle(self):
        """
        In this initial state, the server is just listening.
        """


    @machine.input
    def client_hello_received(self):
        """
        
        """


    @machine.state
    def check_session_cache(self):
        """
        
        """

    @machine.input
    def id_found_somehow(self, session_id):
        """
        
        """

    @machine.input
    def id_not_found_somehow(self):
        """
        
        """

    @machine.state
    def wait_resume(self):
        """
        We are waiting for the client to send finished; we are resuming a
        session.
        """


    @machine.state
    def wait(self):
        """
        We are waiting for the client to send finished; we are initiating a new
        session.
        """


    @machine.output
    def send_server_hello(self, session_id=None):
        """
        
        """


    @machine.output
    def send_server_hello_done(self):
        """
        Send all the messages included in the same record as ServerHelloDone,
        since they are all sent in a single round trip, there is no waiting for
        the client to send us anything back in the middle.

        In other words, send the data required to initiate a new session with
        the client.
        """


    @machine.output
    def send_finished(self):
        """
        Send the ChangeCipherSpec and Finished.
        """


    @machine.input
    def received_finished(self):
        """
        The client sent us a Finished message.
        """


    @machine.output
    def send_no_renegotiation(self):
        """
        Send a TLS Alert(no_renegotiation).
        """


    machine.transitions(
        [idle],
        [
            (idle, client_hello_received, check_session_cache, []),

            # old session, we can finish immediately
            (check_session_cache, id_found_somehow, wait_resume,
             [send_server_hello, send_finished]),

            # new session, we send ServerHelloDone and wait for client Finished
            # before we can send Finished.
            (check_session_cache, id_not_found_somehow, wait,
             [send_server_hello, send_server_hello_done]),

            (wait, received_finished, TLSCommon.app_data, [send_finished]),
            (wait_resume, received_finished, TLSCommon.app_data, []),

            (TLSCommon.app_data, client_hello_received, TLSCommon.app_data,
             [send_no_renegotiation]),
        ],
        [TLSCommon.shutdown],
    )


def example_usage():
    """
    Some sketches of how this might be used.
    """
    client = TLSClient()
    client.begin()
    client.receive_finished()
