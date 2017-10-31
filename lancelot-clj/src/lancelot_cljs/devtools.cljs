(ns lancelot_cljs.devtools
  (:require [devtools.core :as devtools]))

(devtools/set-pref! :fn-symbol "F")
(devtools/set-pref! :print-config-overrides true)
(devtools/install! [:formatters :hints])
