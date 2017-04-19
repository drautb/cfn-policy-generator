#lang racket

(require json
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

(define ALLOW-POST-HEADER
  (make-header #"Allow" #"POST"))

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
            empty
            identity))

(define METHOD-NOT-ALLOWED
  (response 405
            #"Method Not Allowed"
            (current-seconds)
            TEXT/HTML-MIME-TYPE
            (list ALLOW-POST-HEADER)
            identity))

(define (good-response policy-hash)
  (response 200
            #"Ok"
            (current-seconds)
            APPLICATION/JSON
            empty
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
    (cond [(equal? (request-method request) POST)
           (let ([content-type-header (headers-assq* CONTENT-TYPE (request-headers/raw request))])
             (if (header? content-type-header)
                 (let ([content-type (header-value content-type-header)])
                   (cond [(equal? content-type APPLICATION/JSON)
                          (begin
                            (define body-json (string->jsexpr body-str))
                            (let ([policy-hash (generate-policy body-json)])
                              (good-response policy-hash)))]
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

    )

  (run-tests test-http-responses))
