#lang racket

(require json
         yaml
         web-server/servlet
         "policy-generator.rkt")

(provide handle-request)

;; https://www.quora.com/What-is-the-correct-MIME-type-for-YAML-documents
(define APPLICATION/X-YAML #"application/x-yaml")
(define APPLICATION/JSON  #"application/json")

(define GET #"GET")
(define POST #"POST")
(define PUT #"PUT")
(define PATCH #"PATCH")
(define DELETE #"DELETE")
(define OPTIONS #"OPTIONS")

(define ALLOW-POST-HEADER
  (make-header #"Allow" #"POST"))

(define RESPONSE-HEADERS
  (list (make-header #"Access-Control-Allow-Origin" #"*")
        (make-header #"Access-Control-Allow-Headers" #"Content-Type")
        (make-header #"Access-Control-Allow-Methods" #"POST")))

(define CONTENT-TYPE #"Content-Type")

(define JSON-CONTENT-TYPE-HEADER
  (make-header CONTENT-TYPE APPLICATION/JSON))

(define YAML-CONTENT-TYPE-HEADER
  (make-header CONTENT-TYPE APPLICATION/X-YAML))

;; Canned responses
(define BAD-REQUEST
  (response 400
            #"Bad Request"
            (current-seconds)
            TEXT/HTML-MIME-TYPE
            RESPONSE-HEADERS
            identity))

(define METHOD-NOT-ALLOWED
  (response 405
            #"Method Not Allowed"
            (current-seconds)
            TEXT/HTML-MIME-TYPE
            (append (list ALLOW-POST-HEADER)
                    RESPONSE-HEADERS)
            identity))

(define (good-response policy-hash)
  (response 200
            #"Ok"
            (current-seconds)
            APPLICATION/JSON
            RESPONSE-HEADERS
            (λ (op)
              (write-json policy-hash op))))

(define (handle-request request)
  (with-handlers
    ([exn:fail? (lambda (exn)
                  (log-warning "An error occurred. ~a" (exn-message exn))
                  BAD-REQUEST)])
    (log-info "Request received. method=~a uri=~a host-ip=~a client-ip=~a headers=~a"
              (request-method request)
              (url->string (request-uri request))
              (request-host-ip request)
              (request-client-ip request)
              (request-headers request))
    (define body-str (bytes->string/utf-8 (request-post-data/raw request)))
    (cond [(equal? (request-method request) OPTIONS)
           (response 200 #"Ok" (current-seconds) TEXT/HTML-MIME-TYPE (list ALLOW-POST-HEADER) identity)]
          [(equal? (request-method request) POST)
           (let ([content-type-header (headers-assq* CONTENT-TYPE (request-headers/raw request))])
             (if (header? content-type-header)
                 (let ([content-type (header-value content-type-header)])
                   (cond [(equal? content-type APPLICATION/JSON)
                          (begin
                            (define body-json (string->jsexpr body-str))
                            (let ([policy-hash (generate-policy body-json)])
                              (good-response policy-hash)))]
                         [(equal? content-type APPLICATION/X-YAML)
                          (begin
                            (define body-yaml (string->yaml body-str))
                            (if (hash? body-yaml)
                                (let ([policy-hash (generate-policy body-yaml)])
                                  (good-response policy-hash))
                                (begin
                                  (log-warning "Parsed YAML is not a map! yaml=~a" body-yaml)
                                  BAD-REQUEST)))]
                         [else
                          (begin
                            (log-warning "Unrecognized content-type! content-type=~a" content-type)
                            BAD-REQUEST)]))
                 (begin
                   (log-warning "No content-type header found!")
                   BAD-REQUEST)))]
          [else
           (begin
             (log-warning "Method not allowed! method=~a" (request-method request))
             METHOD-NOT-ALLOWED)])))

(module+ test
  (require rackunit
           rackunit/text-ui)

  (define (build-request method headers body)
    (request method
             (string->url "http://url")
             headers
             (delay empty)
             body
             "" 0 ""))

  (define GET-REQUEST (build-request #"GET" empty #""))
  (define PUT-REQUEST (build-request #"PUT" empty #""))
  (define PATCH-REQUEST (build-request #"PATCH" empty #""))
  (define DELETE-REQUEST (build-request #"DELETE" empty #""))
  (define OPTIONS-REQUEST (build-request #"OPTIONS" empty #""))

  (define (check-405 request)
    (define r (handle-request request))
    (check-eq? (response-code r) 405)
    (check-eq? (first (member ALLOW-POST-HEADER (response-headers r)))
               ALLOW-POST-HEADER))

  (define-test-suite test-http-responses

    (test-case "GET should return 405 with correct Allow header"
      (check-405 GET-REQUEST))

    (test-case "PUT should return 405 with correct Allow header"
      (check-405 PUT-REQUEST))

    (test-case "PATCH should return 405 with correct Allow header"
      (check-405 PATCH-REQUEST))

    (test-case "DELETE should return 405 with correct Allow header"
      (check-405 DELETE-REQUEST))

    (test-case "Should return 200 for OPTIONS with Allow Post"
      (define r (handle-request OPTIONS-REQUEST))
      (check-eq? (response-code r) 200)
      (check-eq? (first (member ALLOW-POST-HEADER (response-headers r)))
                 ALLOW-POST-HEADER))

    (test-case "Well-formed POST request should return 200"
      (define r (handle-request (build-request #"POST"
                                               (list (make-header CONTENT-TYPE #"application/json"))
                                               #"{}")))
      (check-eq? (response-code r) 200))

    (test-case "Should return 400 if content-type header is missing"
      (define r (handle-request (build-request #"POST"
                                               empty
                                               #"{}")))
      (check-eq? (response-code r) 400))

    (test-case "Should return 400 if content-type is present, but not recognized"
      (define r (handle-request (build-request #"POST"
                                               (list (make-header #"Content-Type" #"blah-blah-blah"))
                                               #"{}")))
      (check-eq? (response-code r) 400))

    (test-case "Should return 400 if content-type is json, but body is not"
      (define r (handle-request (build-request #"POST"
                                               (list (make-header CONTENT-TYPE #"application/json"))
                                               #"hey")))
      (check-eq? (response-code r) 400))

    (test-case "Should return 400 if content-type is yaml, but body is not a map"
      (define r (handle-request (build-request #"POST"
                                               (list (make-header CONTENT-TYPE #"application/x-yaml"))
                                               #"asdf")))
      (check-eq? (response-code r) 400))

    )

  (run-tests test-http-responses))
