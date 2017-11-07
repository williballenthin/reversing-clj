(ns lancelot-cljs.subs
  (:require [re-frame.core :refer [reg-sub subscribe]]
            ))

(reg-sub
 :initialized?
 (fn [db _]
   (or (some? (:samples db)))))

(reg-sub
 :samples-loaded?
 (fn [db _]
   (some? (:samples db))))

(reg-sub
 :sample-selected?
 (fn [db _]
   (some? (:sample db))))

;; Returns:
;;   [{:md5 str :sha1 str} ...]
(reg-sub
 :samples
 (fn [db _]
   (:samples db)))

;; Returns:
;;
;;     {:md5 str :sha1 str}
(reg-sub
 :sample
 (fn [db _]
   (:sample db)))

(reg-sub
 :functions-loaded?
 (fn [db _]
   (prn "functions-loaded?" (some? (:functions db)))
   (some? (:functions db))))

(reg-sub
 :function-selected?
 (fn [db _]
   (prn "function-selected?" (some? (:functions db)))
   (some? (:function db))))

;; Returns:
;;
;;     [{:va int}]
(reg-sub
 :functions
 (fn [db _]
   (:functions db)))

;; Returns:
;;
;;     int
(reg-sub
 :function
 (fn [db _]
   (:function db)))

(reg-sub
 :blocks
 (fn [db _]
   (:blocks db)))

(reg-sub
 :edges
 (fn [db _]
   (:edges db)))

(reg-sub
 :insns
 (fn [db _]
   (:insns db)))

(reg-sub
 :function-loaded?
 (fn [db _]
   (some? (:insns db))))
