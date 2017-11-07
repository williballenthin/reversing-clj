(ns lancelot-cljs.views
  (:require [reagent.core  :as reagent]
            [re-frame.core :refer [subscribe dispatch]]
            [clojure.string :as str]
            ))

(def <sub (comp deref re-frame.core/subscribe))
(def >evt re-frame.core/dispatch)

(defn hex-format
  [n]
  (str "0x" (str/upper-case (.toString n 16))))


(defn canvas
  ([meta children]
   (let [state (reagent/atom {:dragging false  ; is the user currently dragging?
                              :drag-x 0        ; the x delta since the user started dragging, 0 if not dragging
                              :drag-y 0        ; the y delta since the user started dragging, 0 if not dragging
                              :shift-left 0    ; the x translation of the canvas
                              :shift-top 0     ; the y translation of the canvas
                              :zoom 1.0})]     ; the zoom scale of the canvas
     (fn []
       [:div.canvas-viewport
        (merge
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
         } meta)
        [:div.canvas
         {:style {:transform
                  (let [{:keys [zoom drag-x drag-y shift-left shift-top]} @state]
                    (str
                     "translate(" (+ drag-x shift-left) "px, "
                                  (+ drag-y shift-top)  "px) "
                     "scale(" zoom  ") "
                     ))}}
         children]])))
  ([children] (canvas {} children))
  ([] (canvas {} [:div.empty])))


(def sqrt (.-sqrt js/Math))
(def PI (.-PI js/Math))
(def atan2 (.-atan2 js/Math))

;; these line drawing algorithms ripped directly from:
;;  http://stackoverflow.com/questions/4270485/drawing-lines-on-html-page

(defn geoline
  [x y length angle]
  [:div.line
   {:style {:width (str length "em")
            :transform (str "rotate(" angle "rad)")
            :top (str y "em")
            :left (str x "em")}}])

(defn line
  [x2 y2 x1 y1]
  (let [a (- x1 x2)
        b (- y1 y2)
        c (sqrt
           (+
            (* a a)
            (* b b)))
        sx (/ (+ x1 x2) 2)
        sy (/ (+ y1 y2) 2)
        x (- sx (/ c 2))
        y sy
        alpha (- PI (atan2 (- b) a))]
    (geoline x y c alpha)))

(defn multi-line
  [props children]
  (let [class (:class props)
        class (if class
                (str "multi-line " class)
                "multi-line")]
    [:div
     {:class class}
     children]))

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

(defn basic-block
  [va]
  (let [block @(subscribe [:basic-block va])]
    [:div.basic-block
     [:div.bb-header "basic block " (hex-format (:va block))]
     [:div.bb-content
      [:table
       [:thead]
       [:tbody
        (for [insn (:insns block)]
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

(defn compute-bb-height
  "
  units: em
  "
  [bb]
  (let [insn-count (count (:insns bb))
        ;; assume header size is 1em,
        ;; which is defined in the css style.
        header-size 1]
    (+ header-size insn-count)))

(defn compute-bb-width
  "
  units: em
  "
  [bb]
  ;; the following constants are defined in the css style.
  (let [padding-1-size 1
        padding-2-size 1
        padding-3-size 1
        padding-4-size 1
        bytes-size 12
        mnem-size 6
        operands-size (apply max (map #(count (:opstr %)) (:insns bb)))
        comments-size (apply max (map #(count (:comments %)) (:insns bb)))]
    (+ padding-1-size
       padding-2-size
       padding-3-size
       padding-4-size
       bytes-size
       mnem-size
       operands-size)))

(defn compute-edges
  [basic-blocks]
  (remove nil?
          (concat
           (for [bb basic-blocks]
             (when (:jump bb)
               {:src (:addr bb) :dst (:jump bb) :type :jump}))
           (for [bb basic-blocks]
             (when (:fail bb)
               {:src (:addr bb) :dst (:fail bb) :type :fail})))))

(defn positioned
  "wrap the given children with a div at the given x-y coordinates"
  [{:keys [x y]} children]
  [:div.laid-out
   {:style {:top (str y "em")
            :left (str x "em")}}
   children])

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
