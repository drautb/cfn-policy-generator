#lang racket

(require json
         web-server/servlet
         web-server/servlet-env
         "policy-generator.rkt")

(define port (make-parameter 8080))

(command-line
 #:program "cfn-policy-generator"
 #:once-each
 [("-p" "--port") listen-on-port "Port to listen on"
  (port (string->number listen-on-port))])

(define APPLICATION/JSON-MIME-TYPE  #"application/json; charset=utf-8")

(define (handle request)
  (log-info "Request received. method=~a uri=~a"
            (request-method request)
            (url->string (request-uri request)))
  (define body-json (with-input-from-bytes (request-post-data/raw request) (λ () (read-json))))
  (cond [(equal? (request-method request) #"POST")
         (let ([policy-hash (generate-policy body-json)])
           (log-info "HASH: ~a~n" policy-hash)
           (response 200
                     #"Ok"
                     (current-seconds)
                     APPLICATION/JSON-MIME-TYPE
                     empty
                     (λ (op)
                       (write-json policy-hash op))))]
        [else
         (response 405
                   #"Method Not Allowed"
                   (current-seconds)
                   TEXT/HTML-MIME-TYPE
                   empty
                   (λ (op) op))]))

(serve/servlet handle
               #:port (port)
               #:servlet-path "/cloudformation/2010-09-09/template"
               #:command-line? #t)
