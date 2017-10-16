(ns lancelot-clj.anal
  (:gen-class)
  (:require [clojure.tools.logging :as log]
            [clojure.set :as set])
  (:import [capstone.X86_const]))


(defn conj-if [c e]
  (if (not (nil? e))
    (conj c e)
    c))


(defn assoc-if [m k e]
  (if (not (nil? e))
    (assoc m k e)
    m))


(defn call?
  [insn]
  (condp = (. insn id)
    capstone.X86_const/X86_INS_CALL true
    capstone.X86_const/X86_INS_LCALL true
    false))


(defn ret?
  [insn]
  (condp = (. insn id)
    capstone.X86_const/X86_INS_RET true
    capstone.X86_const/X86_INS_IRET true
    capstone.X86_const/X86_INS_IRETD true
    capstone.X86_const/X86_INS_IRETQ true
    false))


(defn jmp? [insn] (= (. insn id) capstone.X86_const/X86_INS_JMP))


(def ^:const x86-cjmp-instructions
  #{capstone.X86_const/X86_INS_JAE
    capstone.X86_const/X86_INS_JA
    capstone.X86_const/X86_INS_JBE
    capstone.X86_const/X86_INS_JB
    capstone.X86_const/X86_INS_JCXZ
    capstone.X86_const/X86_INS_JECXZ
    capstone.X86_const/X86_INS_JE
    capstone.X86_const/X86_INS_JGE
    capstone.X86_const/X86_INS_JG
    capstone.X86_const/X86_INS_JLE
    capstone.X86_const/X86_INS_JL
    capstone.X86_const/X86_INS_JNE
    capstone.X86_const/X86_INS_JNO
    capstone.X86_const/X86_INS_JNP
    capstone.X86_const/X86_INS_JNS
    capstone.X86_const/X86_INS_JO
    capstone.X86_const/X86_INS_JP
    capstone.X86_const/X86_INS_JRCXZ
    capstone.X86_const/X86_INS_JS})


(defn cjmp? [insn] (contains? x86-cjmp-instructions (. insn id)))


(defn get-op0
  "fetch the first operand to the instruction"
  [insn]
  (let [[op &rest] (.. insn operands op)]
    op))


;; capstone indexing:
;; given: [eax+10h]
;;   - segment: 0x0
;;   - base: 0x13 (eax)
;;   - index: 0x0
;;   - disp: 0x10


(defn indirect-target?
  [insn]
  (let [op (get-op0 insn)]
    (cond
      ;; jmp eax
      (= (.-type op) capstone.X86_const/X86_OP_REG) true
      ;; jmp [eax+0x10]
      ;; jmp [eax*0x8+0x10]
      (and (= (.-type op) capstone.X86_const/X86_OP_MEM)
           (or (not= (.. op value mem base) capstone.X86_const/X86_REG_INVALID)
               (not= (.. op value mem index) capstone.X86_const/X86_REG_INVALID))) true
      :default false)))


(defn get-target
  "assuming the given instruction has a first operand that is not indirect."
  [insn]
  (let [op (get-op0 insn)]
    (cond
      (= (.-type op) capstone.X86_const/X86_OP_IMM) (.. op value imm)
      ;; should we annotate this value with the `deref`?
      ;; upside: more information.
      ;; downside: inconsistent return value type.
      (= (.-type op) capstone.X86_const/X86_OP_MEM) {:deref (.. op value mem disp)}
      :default nil)))


(defn nop?
  [insn]
  (if (= (.-id insn) capstone.X86_const/X86_INS_NOP)
    true
    (if (not (= (count (.-op (.-operands insn))) 2))
      false
      (let [[op0 op1] (.-op (.-operands insn))]
        (cond
          ;; via: https://github.com/uxmal/nucleus/blob/master/disasm.cc
          (and (= (. insn id) capstone.X86_const/X86_INS_MOV)
               (= (. op0 type) capstone.X86_const/X86_OP_REG)
               (= (. op1 type) capstone.X86_const/X86_OP_REG)
               (= (.. op0 value reg) (.. op1 value reg))) true
          (and (= (. insn id) capstone.X86_const/X86_INS_XCHG)
               (= (. op0 type) capstone.X86_const/X86_OP_REG)
               (= (. op1 type) capstone.X86_const/X86_OP_REG)
               (= (.. op0 value reg) (.. op1 value reg))) true
          (and (= (. insn id) capstone.X86_const/X86_INS_LEA)
               (= (. op0 type) capstone.X86_const/X86_OP_REG)
               (= (. op1 type) capstone.X86_const/X86_OP_MEM)
               (= (.. op1 value mem segment) capstone.X86_const/X86_REG_INVALID)
               (= (.. op1 value mem base) (.. op0 value reg))
               (= (.. op1 value mem index) capstone.X86_const/X86_REG_INVALID)
               (= (.. op1 value mem disp) 0)) true
          :default false)))))



(defn analyze-instruction-flow
  [insn]
  (-> #{}
      (conj-if (when (not (or (ret? insn)
                              (jmp? insn)))
                 {:type :fall-through
                  :address (+ (. insn address) (. insn size))}))
      (conj-if (when (and (jmp? insn)
                          (not (indirect-target? insn)))
                 {:type :jmp
                  :address (get-target insn)}))
      (conj-if (when (and (cjmp? insn)
                          (not (indirect-target? insn)))
                 {:type :cjmp
                  :address (get-target insn)}))))


(defn analyze-instruction
  "
  extract features from the given capstone instruction instance.

  Returns:
    map: keys:
      - :flow - set of flow references (fallthrough, jmp, cjmp).
      - :cref - set of code references (calls).
      - :insn - capstone instruction instance.
      - :address - va of instruction.
  "
  [insn]
  (-> {:flow (analyze-instruction-flow insn)}
      (assoc-if :cref (when (and (call? insn)
                                 (not (indirect-target? insn)))
                        #{{:address (get-target insn)}}))
      (assoc :insn insn)
      (assoc :address (.address insn))))


(defn thunk?
  [address]
  (and (map? address)
       (contains? address :deref)))

