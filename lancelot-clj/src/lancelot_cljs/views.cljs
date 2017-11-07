(ns lancelot-cljs.views
  (:require [reagent.core  :as reagent]
            [re-frame.core :refer [subscribe dispatch]]
            [clojure.string :as str]
            ))

(defn hex-format
  [n]
  (str "0x" (str/upper-case (.toString n 16))))

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
                         (hex-format va)]))])

(defn insn-list
  [insns]
  [:ul
   (for [insn (sort :va insns)]
     (let [va (:va insn)]
       ^{:key va} [:div (str (hex-format va) " " (:mnem insn) " " (:opstr insn))]))])

(def <sub (comp deref re-frame.core/subscribe))
(def >evt re-frame.core/dispatch)

(defn basic-block
  [va]
  (let [block @(subscribe [:basic-block va])]
    [:div.basic-block
     [:div.bb-header "basic block " (hex-format (:va (<sub [:basic-block va])))]
     [:div.bb-content
      [:table
       [:thead]
       [:tbody
        (for [insn (:insns @(subscribe [:basic-block va]))]
          ^{:key (:va insn)}
          [:tr.insn
           [:td.addr (hex-format (:va insn))]
           [:td.padding-1]
           ;; TODO: re-enable bytes
           [:td.bytes #_(str/upper-case (:bytes insn))]
           [:td.padding-2]
           [:td.mnem (:mnem insn)]
           [:td.padding-3]
           [:td.operands (:opstr insn)]
           [:td.padding-4]
           [:td.comments (when (and (:comments insn)
                                    (not= "" (:comments insn)))
                           (str ";  " (:comments insn)))]])]]]]))

(defn canvas [children]
  (let [state (reagent/atom {:dragging false  ; is the user currently dragging?
                             :drag-x 0        ; the x delta since the user started dragging, 0 if not dragging
                             :drag-y 0        ; the y delta since the user started dragging, 0 if not dragging
                             :shift-left 0    ; the x translation of the canvas
                             :shift-top 0     ; the y translation of the canvas
                             :zoom 1.0})]     ; the zoom scale of the canvas
    (fn []
      [:div.canvas-viewport
       {:on-wheel
        (fn [e]
          (.preventDefault e)
          (let [delta (aget e "deltaY")]
            (if (> 0 delta)
              (swap! state update :zoom #(* 1.1 %))
              (swap! state update :zoom #(* (/ 1 1.1) %)))))
        :on-mouse-down
        (fn [e]
          (.preventDefault e)
          (let [evt (or e (js/event))
                client-x (aget evt "clientX")
                client-y (aget evt "clientY")]
            (swap! state merge {:dragging true
                                :down-x client-x
                                :down-y client-y
                                :drag-x 0
                                :drag-y 0})))
        :on-mouse-up
        (fn [e]
          (.preventDefault e)
          (let [evt (or e (js/event))
                client-x (aget evt "clientX")
                client-y (aget evt "clientY")]
            (swap! state #(-> %
                              (dissoc :down-x)
                              (dissoc :down-y)
                              (merge {:dragging false
                                      :drag-x 0
                                      :drag-y 0
                                      :shift-left (+ (:shift-left @state)
                                                     (- client-x (:down-x @state)))
                                      :shift-top (+ (:shift-top @state)
                                                    (- client-y (:down-y @state)))})))))
        :on-mouse-move
        (fn [e]
         (.preventDefault e)
         (when (:dragging @state)
           (let [evt (or e (js/event))
                 client-x (aget evt "clientX")
                 client-y (aget evt "clientY")]
             (swap! state merge {:drag-x (- client-x (:down-x @state))
                                 :drag-y (- client-y (:down-y @state))}))))
       }
       [:div.canvas
        {:style {:transform
                 (let [{:keys [zoom drag-x drag-y shift-left shift-top]} @state]
                   (str
                    "translate(" (+ drag-x shift-left) "px, "
                                 (+ drag-y shift-top)  "px) "
                    "scale(" zoom  ") "
                    ))}}
        children
        ]])))

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
      [:section#basic-blocks
       [:h3 "basic blocks:"]
       [canvas
         (doall (for [va @(subscribe [:blocks])]
                  ^{:key va}
                  [basic-block va]))]])
    ]])

