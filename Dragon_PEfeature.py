# -*- coding: utf-8 -*-
#################### Dragon_PEfeature.py —— 重构后 PE 特征提取门面 ####################
"""
依据《引擎重构开发文档.md》第四节：第四层（L4）改用 SevenEngine 的 LightGBM 树模型
（.pda 模型），特征提取复用 SevenEngine 的 512 维抽取器（原 ONNX/onnx_feature_extractor.py，
已随买断引擎授权直抄为 dragon_pda_features.py）。

本模块是 L4 特征抽取的**对外门面（facade）**：上层引擎、UI、调试脚本统一从这里取 PE
特征，不直接 import vendor 内部模块。这样做与重构文档一致 —— V2 不再有独立的 3072 维
PE 特征库，特征维度固定为 SevenEngine 的 512 维。

公共 API：
    FEATURE_SIZE / PE_FEATURE_DIM   512
    pe_extract(path, data, max_read)  返回 512 维特征向量(list[float])
    pe_vector(path)                   兼容旧调用的别名
    feature_size()                    返回 512
"""
from dragon_pda_features import extract_features, FEATURE_SIZE

# 对外稳定常量（与 vendor 模块保持一致）
FEATURE_SIZE = FEATURE_SIZE          # 512
PE_FEATURE_DIM = FEATURE_SIZE


def pe_extract(path=None, data=None, max_read=65536):
    """抽取单个样本的 512 维特征向量（list[float]）。

    path: 待分析文件路径（与 data 二选一）
    data: 已读入的字节内容（与 path 二选一，优先）
    max_read: 最大读取字节数（与 vendor 默认一致，65536）
    """
    return extract_features(filepath=path, file_data=data, max_read=max_read)


def pe_vector(path):
    """兼容旧调用：返回 PE/样本文件的 512 维特征向量。"""
    return extract_features(filepath=path)


def feature_size():
    """返回特征维度（512）。"""
    return FEATURE_SIZE
