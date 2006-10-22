;; This is not a stand-alone guile application.
;; It can only be executed from within gnunet-setup.
;;
;; GNUnet setup defines a function "build-tree-node"
;; (with arguments section, option, description, help,
;;  children, visible, value and range) which is
;;  used by the script to create the configuration tree.
;;
;; GNUnet setup defines a function "change-visible"
;; (with arguments context, section, option, yesno) which
;;  can be used by the script to dynamically change the
;;  visibility of options.
;;
;; GNUnet setup defines a function "get-option"
;; (with arguments context, section, option) which
;;  can be used to query the current value of an option.
;;
;; GNUnet setup defines a function "set-option"
;; (with arguments context, section, option, value) which
;;  can be used to set the value of an option.
;;
;;
;; GNUnet setup requires two functions from this script.
;; First, a function "gnunet-config-setup" which constructs the
;; configuration tree.
;;
;; Second, a function "gnunet-config-change" which is notified whenever
;; configuration options are changed; the script can then
;; change the visibility of other options.
;;
;;
;; TODO:
;; - complete conversion of *.in to *.scm



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; for GNU gettext
(define (_ msg) (gettext msg "GNUnet"))

;; common string
(define (nohelp) 
  (_ "No help available.") )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; menu definitions

;; meta-menu

(define (meta-exp builder) 
 (builder
   "Meta-client"
   "EXPERIMENTAL"
   (_ "Prompt for development and/or incomplete code")
   (_
"If EXPERIMENTAL is set to NO, options for experimental code are not shown.  If in doubt, use NO.

Some options apply to experimental code that maybe in a state of development where the functionality, stability, or the level of testing is not yet high enough for general use.  These features are said to be of \"alpha\" quality.  If a feature is currently in alpha, uninformed use is discouraged (since the developers then do not fancy \"Why doesn't this work?\" type messages).

However, active testing and qualified feedback of these features is always welcome.  Users should just be aware that alpha features may not meet the normal level of reliability or it may fail to work in some special cases.  Bug reports are usually welcomed by the developers, but please read the documents <file://README> and <http://gnunet.org/faq.php3> and use <https://gnunet.org/mantis/> for how to report problems." )
   '()
   #t
   #f
   #f
   'advanced) )

(define (meta-adv builder) 
 (builder
   "Meta-client"
   "ADVANCED"
   (_ "Show options for advanced users")
   (_
"These are options that maybe difficult to understand for the beginner. These options typically refer to features that allow tweaking of the installation.  If in a hurry, say NO." )
   '()
   #t
   #t
   #f
   'always) )

(define (meta-rare builder) 
 (builder
   "Meta-client"
   "RARE"
   (_ "Show rarely used options")
   (_
"These are options that hardly anyone actually needs.  If you plan on doing development on GNUnet, you may want to look into these.  If in doubt or in a hurry, say NO." )
   '()
   #t
   #t
   #f
   'advanced) )

(define (meta builder)
 (builder
   "Meta-client"
   "" 
   (_ "Meta-configuration") 
   (_ "Which level of configuration should be available")
   (list 
     (meta-adv builder) 
     (meta-rare builder)
     (meta-exp builder)
   )
   #t
   #f
   #f
   'always) )


;; logging options

(define (log-conf-user-urgency-severity-logger description user urgency severity logger builder def opt)
 (builder
   "LOGGING"
   (string-append user "-" urgency "-" severity "-" logger)
   description
   ""
   '()
   #t
   def
   opt
   (if (string=? urgency "STDOUT") 'rare 'always)))


;; FIXME: set default to /dev/null for DEVELOPER, INFO, STATUS and REQUEST file-logs
(define (log-conf-user-urgency-severity description user urgency severity builder)
 (builder
   "LOGGING"
   (string-append user "-" urgency "-" severity)
   description
   ""
   (list
     (log-conf-user-urgency-severity-logger (_"Log using standard error (YES/NO)") user urgency severity "STDERR" builder #f #f)
     (log-conf-user-urgency-severity-logger (_"Log using standard output (YES/NO)") user urgency severity "STDOUT" builder #f #f)
     (log-conf-user-urgency-severity-logger (_"Log this event type to a file (specify filename)") user urgency severity "FILE" builder "~/.gnunet/logs" '())
   )
   #t
   #f
   #f
   (if (string=? severity "DEBUG") 'rare 
     (if (string=? severity "STATUS") 'advanced
        (if (string=? severity "INFO") 'advanced 'always )))))

(define (log-conf-user-urgency description user urgency builder)
 (builder
   "LOGGING"
   (string-append user "-" urgency)
   description
   ""
   (list
     (log-conf-user-urgency-severity (_"Logging of events that are fatal to some operation") user urgency "FATAL" builder)
     (log-conf-user-urgency-severity (_"Logging of non-fatal errors") user urgency "ERROR" builder)
     (log-conf-user-urgency-severity (_"Logging of warnings") user urgency "WARNING" builder)
     (log-conf-user-urgency-severity (_"Logging of information messages") user urgency "INFO" builder)
     (log-conf-user-urgency-severity (_"Logging of status messages") user urgency "STATUS" builder)
     (log-conf-user-urgency-severity (_"Logging of debug messages") user urgency "DEBUG" builder)
   )
   #t
   #f
   #f
   (if (string=? urgency "REQUEST") 'rare 'always)))

(define (log-conf-user description user builder)
 (builder
   "LOGGING"
   user
   description
   ""
   (list
     (log-conf-user-urgency (_"Logging of events that usually require immediate attention") user "IMMEDIATE" builder)
     (log-conf-user-urgency (_"Logging of events that can be processed in bulk") user "BULK" builder)
     (log-conf-user-urgency (_"Logging of events that are to be shown only on request") user "REQUEST" builder)
   )
   #t
   #f
   #f
   (if (string=? user "DEVELOPER") 'advanced 'always)))

(define (log-conf-date builder)
 (builder
   "LOGGING"
   "DATE"
   (_ "Log the date of the event")
   (nohelp)
   '()
   #t
   #t
   #t
   'advanced))

(define (log-keeplog builder)
 (builder
  "GNUNETD"
  "KEEPLOG"
  (_ "How long should logs be kept?")
  (_ 
"How long should logs be kept? If you specify a value greater than zero, a log is created each day with the date appended to its filename. These logs are deleted after $KEEPLOG days.	To keep logs forever, set this value to 0." )
  '()
  #t
  3
  (cons 0 36500)
  'advanced) )

(define (logging builder)
 (builder
   "LOGGING"
   "" 
   (_ "Configuration of the logging system") 
   (_ "Specify which system messages should be logged how")
   (list 
     (log-conf-date builder)
     (log-keeplog builder)
     (log-conf-user (_ "Logging of events for users") "USER" builder) 
     (log-conf-user (_ "Logging of events for the system administrator") "ADMIN" builder) 
     (log-conf-user (_ "Logging of events for developers") "DEVELOPER" builder) 
   )
   #t
   #f
   #f
   'always) )


;; main-menu

(define (main builder)
 (builder 
  "Root"
  ""
  (_ "Root node")
  (nohelp)
  (list 
    (meta builder)
    (logging builder)
  )
  #t 
  #f 
  #f 
  'always) )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; first main method: build tree using build-tree-node
;; The lambda expression is used to throw away the last argument,
;; which we use internally and which is not used by build-tree-node!
(define (gnunet-config-setup) 
 (main 
  (lambda (a b c d e f g h i) (build-tree-node a b c d e f g h) ) ) )


;; second main method: update visibility (and values)
;; "change" uses again the tree builder but this time
;; scans the "i" tags to determine how the visibility needs to change

(define (gnunet-config-change ctx)
 (let 
   ( 
     (advanced (get-option ctx "Meta-client" "ADVANCED"))
     (rare (get-option ctx "Meta-client" "RARE"))
     (experimental (get-option ctx "Meta-client" "EXPERIMENTAL"))
   )
  (begin 
    (main
     (lambda (a b c d e f g h i) 
        (begin 
          (cond
            ((eq? i 'advanced)     (change-visible ctx a b advanced))
            ((eq? i 'rare)         (change-visible ctx a b rare))
            ((eq? i 'experimental) (change-visible ctx a b experimental))
            (else 'nothing)
          )
   ) ) ) )
) )

