(ns lancelot_cljs.core
  (:require [goog.events :as events]
            [reagent.core :as reagent]
            [re-frame.core :refer [dispatch dispatch-sync]]
            [secretary.core :as secretary]
            [lancelot_cljs.events]
            [lancelot_cljs.subs]
            [lancelot_cljs.views]
            [devtools.core :as devtools]))

(devtools/install!)
(enable-console-print!)

;; -- Entry Point -------------------------------------------------------------
;; Within ../../resources/public/client/index.html you'll see this code
;;    window.onload = function () {
;;      lancelot_cljs.core.main();
;;    }
;; So this is the entry function that kicks off the app once the HTML is loaded.
;;
(defn ^:export main
  []
  ;; Put an initial value into app-db.
  ;; The event handler for `:initialize-db` can be found in `events.cljs`
  ;; Using the sync version of dispatch means that value is in
  ;; place before we go onto the next step.
  (dispatch-sync [:initialize-db])

  (dispatch [:load-samples])

  ;; Render the UI into the HTML's <div id="app" /> element
  ;; The view function `lancelot_cljs.views/dis-app` is the
  ;; root view for the entire UI.
  (reagent/render [lancelot_cljs.views/dis-app]
                  (.getElementById js/document "app")))
