#lang racket

(require json
         web-server/servlet
         web-server/servlet-env
         "policy-generator.rkt")

(define PORT
  (let ([port (environment-variables-ref (current-environment-variables) #"PORT")])
    (if port
        (string->number (bytes->string/utf-8 port))
        5000)))

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

(log-info "Starting server on port=~a" PORT)
(serve/servlet handle
               #:port PORT
               #:servlet-path "/cloudformation/2010-09-09/template"
               #:command-line? #t)
