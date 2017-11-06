(ns lancelot-cljs.views
  (:require [reagent.core  :as reagent]
            [re-frame.core :refer [subscribe dispatch]]
            [clojure.string :as str]
            ))

(defn sample-list
  [samples]
  [:section#samples
   [:h1 "samples:"]
   [:ul
    (for [sample samples]
      ^{:key (:md5 sample)} [:div
                             {:on-click #(dispatch [:select-sample (:md5 sample)])}
                             (:md5 sample)])]])

(defn function-list
  [functions]
  [:ul
    (for [function functions]
      (let [va (:va function)]
        ^{:key va} [:div {:on-click #(dispatch [:select-function va])}
                         (str va)]))])

(defn insn-list
  [insns]
  [:ul
   (for [insn (sort :va insns)]
     (let [va (:va insn)]
       ^{:key va} [:div (str va " " (:mnem insn) " " (:opstr insn))]))])

(defn dis-app
  []
  [:div
   [:section#dis-app
    [:section#hello "Hello world!"]
    (if (not @(subscribe [:samples-loaded?]))
      [:section#loading-samples "loading samples..."]
      (sample-list @(subscribe [:samples])))
    (when @(subscribe [:sample-selected?])
      [:div#sample
       [:h1 @(subscribe [:sample])]
       (if (not @(subscribe [:functions-loaded?]))
         [:section#loading-functions "loading functions..."]
         [:section#functions
          [:h2 "functions:"]
          (function-list @(subscribe [:functions]))])])
    (when @(subscribe [:function-loaded?])
      [:section#insns
       [:h3 "instructions:"]
       (insn-list @(subscribe [:insns]))])]])

