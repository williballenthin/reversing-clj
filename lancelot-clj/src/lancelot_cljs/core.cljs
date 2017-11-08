(ns lancelot_cljs.core
  (:require [goog.events :as events]
            [reagent.core :as reagent]
            [re-frame.core :refer [dispatch dispatch-sync subscribe]]
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
  (when (not @(subscribe [:initialized?]))
    (dispatch-sync [:initialize-db])
    (dispatch [:load-samples]))
  ;; Render the UI into the HTML's <div id="app" /> element
  ;; The view function `lancelot_cljs.views/dis-app` is the
  ;; root view for the entire UI.
  (reagent/render [lancelot_cljs.views/dis-app]
                  (.getElementById js/document "app")))
