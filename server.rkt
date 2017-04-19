#lang racket

(require json
         web-server/servlet
         web-server/servlet-env
         "request-handler.rkt")

(define PORT
  (let ([port (environment-variables-ref (current-environment-variables) #"PORT")])
    (if port
        (string->number (bytes->string/utf-8 port))
        5000)))

(log-info "Starting server on port=~a" PORT)
(serve/servlet handle-request
               #:port PORT
               #:listen-ip #f
               #:servlet-path "/cloudformation/2010-09-09/template"
               #:command-line? #t)
