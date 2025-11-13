
```mermaid
graph TB
  subgraph 全局状态
    A[file_whitelist_root<br/>结构: file_whitelist_node<br/>name="" type=DIR allowed=?]
    B[file_whitelist_lock<br/>rwlock_t]
    C[file_whitelist_count<br/>size_t]
  end

  A -->|拥有| D[children: struct rb_root]
  D -->|rb_root.rb_node| E1[left 子树]
  D -->|rb_root.rb_node| E2[right 子树]

  subgraph 目录节点
    E[file_whitelist_node]
    E -->|字段| F[rb: struct rb_node<br/>(嵌入父目录的红黑树)]
    E -->|字段| G[parent: 指向上一层目录]
    E -->|字段| H[type=FILE/ DIR]
    E -->|字段| I[allowed: bool<br/>目录=子树放行]
    E -->|字段| J[name_len + name[]]
    E -->|字段| K[children: struct rb_root<br/>仅当 type=DIR 时非空<br/>存放直接子节点的红黑树]
  end

  subgraph 文件节点
    L[file 节点<br/>type=FILE]
    L -->|children 为 RB_ROOT 空树| M[无子节点]
    L -->|parent| E
    L -->|rb| F
  end

  style E fill:#f6f9ff,stroke:#3b6,stroke-width:1px
  style L fill:#fff6f6,stroke:#c33,stroke-width:1px
```